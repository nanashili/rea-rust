//! Isolated runtime adapter for the public `extract_firmware` workflow.
//!
//! The native runtime does not own an Unblob process, an extraction workspace,
//! or publication of extracted files.  This adapter therefore accepts the
//! caller's validated request together with the complete producer report and
//! delegates source binding and result projection to the application producer.
//! It is intentionally not registered with the shared MCP composition until
//! the migration boundary and provider authority have been approved.

use rea_application::firmware;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The stable public operation name.
pub const OPERATION: &str = firmware::extraction::OPERATION;

/// Project a caller-supplied extraction report through the public workflow.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let envelope = request_envelope(input)?;

    // The producer reads only the caller-selected immutable source to bind
    // the selection digest. It does not invoke an extractor or publish files.
    firmware::extraction::extract(envelope.request, envelope.report)
}

struct RequestEnvelope<'a> {
    request: &'a Value,
    report: &'a Value,
}

fn request_envelope(input: &Value) -> Result<RequestEnvelope<'_>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("request envelope must be an object"))?;

    const FIELDS: [&str; 2] = ["request", "report"];
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid_input(
            "request envelope must contain exactly request and report",
        ));
    }

    let request = object
        .get("request")
        .ok_or_else(|| invalid_input("request is required"))?;
    let report = object
        .get("report")
        .ok_or_else(|| invalid_input("report is required"))?;

    if !request.is_object() {
        return Err(invalid_input("request must be an object"));
    }
    if !report.is_object() {
        return Err(invalid_input("report must be an object"));
    }

    Ok(RequestEnvelope { request, report })
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Firmware extraction input is invalid.".into(),
        false,
        "Provide the exact request and complete bounded extractor report and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
