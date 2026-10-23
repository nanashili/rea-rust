//! Offline runtime boundary for `list_jeb_units`.
//!
//! Unit discovery remains owned by the caller's JEB client.  This handler only
//! projects a caller-supplied captured page or an authenticated retained
//! Evidence record; it never contacts JEB or reconstructs missing unit facts.

use rea_application::jeb;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{value::to_raw_value, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = jeb::units::OPERATION;

/// Project a captured JEB page or authenticated retained Evidence.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    if let Some(evidence) = input.get("evidence") {
        return project_evidence(evidence);
    }

    if input.get("evidence_id").is_some() {
        return project_evidence(&input);
    }

    if input.get("engine").is_some() {
        return jeb::units::normalize_value(&input);
    }

    for key in ["normalized_result", "result", "value"] {
        if let Some(result) = input.get(key) {
            return jeb::units::normalize_value(result);
        }
    }

    Err(invalid("captured JEB unit inventory or authenticated Evidence is required"))
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

    validate_provider(evidence_object.get("provider"))?;

    let raw = to_raw_value(evidence)
        .map_err(|_| invalid("JEB Evidence could not be represented canonically"))?;
    let authenticated = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("JEB Evidence authentication failed: {error}")))?;

    let normalized_result: Value = serde_json::from_str(authenticated.normalized_result().get())
        .map_err(|_| invalid("JEB Evidence normalized_result is not valid JSON"))?;
    jeb::units::normalize_value(&normalized_result).map_err(|error| {
        invalid(&format!("JEB Evidence contains an invalid unit inventory: {error}"))
    })
}

fn validate_provider(provider: Option<&Value>) -> Result<(), Failure> {
    let provider = provider
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("JEB Evidence must include provider identity"))?;

    if provider.get("id").and_then(Value::as_str) != Some("jeb") {
        return Err(invalid("JEB Evidence provider id is not jeb"));
    }

    if provider
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("JEB Evidence provider name is missing"));
    }

    let version = provider
        .get("version")
        .ok_or_else(|| invalid("JEB Evidence provider version is missing"))?;
    if !version.is_null() && version.as_str().is_none() {
        return Err(invalid("JEB Evidence provider version is invalid"));
    }

    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a bounded captured JEB unit page or authenticated retained Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
