//! Exact-name captured-Evidence boundary for `analyze_function`.
//!
//! The provider owns function discovery and decompilation.  This adapter only
//! selects an authenticated retained Evidence record, delegates dossier
//! normalization, and carries the source record alongside the projection.

use rea_application::native::function_analysis_projection;
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = function_analysis_projection::OPERATION;

/// Normalize one captured function Evidence record without provider access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("analyze_function requires captured Evidence"))?;
    validate_evidence(evidence)?;
    let mut projection = function_analysis_projection::normalize(evidence)?;
    projection["source_evidence"] = json!(evidence);
    Ok(projection)
}

fn validate_evidence(value: &Value) -> Result<(), Failure> {
    let evidence = value
        .as_object()
        .ok_or_else(|| invalid("analyze_function Evidence must be an object"))?;
    if evidence.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("analyze_function Evidence has the wrong operation"));
    }
    if evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .is_none()
    {
        return Err(invalid("analyze_function Evidence requires evidence_id"));
    }
    if evidence.get("normalized_result").or_else(|| evidence.get("result")).is_none() {
        return Err(invalid("analyze_function Evidence requires normalized_result"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide captured analyze_function Evidence and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
