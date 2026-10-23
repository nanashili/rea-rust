//! Read-only projection for provider assembly of one analyzed procedure.
//!
//! Disassembly is owned by the provider boundary.  This module validates the
//! retained Evidence and exposes its exact text without opening a database,
//! decoding bytes again, or normalizing provider spelling.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "procedure_assembly";

const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINES: usize = 1_000_000;
const INPUT_FIELDS: &[&str] = &[
    "evidence",
    "assembly",
    "native_observation",
    "procedure",
    "document",
];

/// Validate a caller-selected retained assembly observation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure assembly input must be an object"))?;
    reject_unknown(object)?;

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("assembly"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("procedure assembly Evidence is required"))?;
    validate_evidence(evidence)?;

    if let Some(procedure) = object.get("procedure") {
        let requested = procedure
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("procedure must be a non-empty string"))?;
        let retained = procedure_selection_value(evidence)
            .ok_or_else(|| invalid("assembly Evidence does not identify a procedure"))?;
        if retained != requested {
            return Err(invalid(
                "procedure does not match retained assembly Evidence",
            ));
        }
    }
    if let Some(document) = object.get("document") {
        if !document.is_null()
            && document
                .as_str()
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(invalid("document must be null or a non-empty string"));
        }
    }
    Ok(())
}

/// Validate provider text before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_text(&result)?;
    Ok(result)
}

/// Return the exact retained provider assembly string.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let evidence = input
        .as_object()
        .and_then(|object| {
            object
                .get("evidence")
                .or_else(|| object.get("assembly"))
                .or_else(|| object.get("native_observation"))
        })
        .ok_or_else(|| invalid("procedure assembly Evidence is required"))?;
    Ok(assembly_text(evidence)?.clone())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("procedure assembly Evidence must be an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("Evidence operation is not procedure_assembly"));
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid(
            "procedure assembly Evidence must include evidence_id",
        ));
    }
    validate_text(assembly_text(evidence)?)
}

fn assembly_text(evidence: &Value) -> Result<&Value, Failure> {
    let value = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("assembly"))
        .unwrap_or(evidence);
    validate_text(value)?;
    Ok(value)
}

fn validate_text(value: &Value) -> Result<(), Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid("procedure assembly result must be a string"))?;
    if text.len() > MAX_TEXT_BYTES {
        return Err(invalid("procedure assembly exceeds the output byte limit"));
    }
    if text.lines().count() > MAX_LINES {
        return Err(invalid("procedure assembly exceeds the line limit"));
    }
    Ok(())
}

fn selection_value<'a>(evidence: &'a Value, field: &str) -> Option<&'a str> {
    evidence
        .get("selection")
        .and_then(Value::as_object)
        .and_then(|selection| selection.get(field))
        .and_then(Value::as_str)
        .or_else(|| evidence.get(field).and_then(Value::as_str))
}

fn procedure_selection_value(evidence: &Value) -> Option<&str> {
    selection_value(evidence, "procedure_address")
        .or_else(|| selection_value(evidence, "procedure"))
}

fn reject_unknown(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown procedure assembly input field: {field}"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained procedure_assembly Evidence or provider text within the configured output limit.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
