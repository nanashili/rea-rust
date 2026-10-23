//! Offline runtime boundary for `inspect_jeb_client`.
//!
//! This adapter accepts only a caller-captured JEB client observation or a
//! retained Evidence record. It never contacts, launches, or configures JEB.

use rea_application::jeb;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{value::to_raw_value, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = jeb::client::OPERATION;

/// Project a captured client observation or authenticated retained Evidence.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    if let Some(evidence) = input.get("evidence") {
        return project_evidence(evidence);
    }

    if input.get("evidence_id").is_some() {
        return project_evidence(&input);
    }

    jeb::client::inspect_value(&input)
}

fn project_evidence(evidence: &Value) -> Result<Value, Failure> {
    let evidence_object = evidence
        .as_object()
        .ok_or_else(|| invalid("JEB Evidence must be an object"))?;

    evidence_object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("JEB Evidence requires a non-empty evidence_id"))?;

    let operation = evidence_object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("JEB Evidence requires an operation"))?;
    if operation != OPERATION {
        return Err(invalid("JEB Evidence has the wrong operation"));
    }

    let raw = to_raw_value(evidence)
        .map_err(|_| invalid("JEB Evidence could not be represented canonically"))?;
    let authenticated = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("JEB Evidence authentication failed: {error}")))?;
    let normalized_result: Value = serde_json::from_str(authenticated.normalized_result().get())
        .map_err(|_| invalid("JEB Evidence normalized_result is not valid JSON"))?;

    jeb::client::inspect_value(&normalized_result)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide bounded captured JEB client information or authenticated retained Evidence."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
