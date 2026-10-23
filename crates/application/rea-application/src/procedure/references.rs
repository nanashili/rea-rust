//! Projection of procedure reference edges from retained function Evidence.
//!
//! The provider owns reference discovery and address canonicalization.  This
//! module only selects the requested direction and preserves the provider's
//! edge facts, including unresolved call locations and nullable procedure
//! identities.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};

pub const OPERATION: &str = "procedure_references";
const MAX_REFERENCES: usize = 200_000;

/// Validate a request containing a retained function observation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure reference input must be an object"))?;
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("outgoing");
    if !matches!(direction, "incoming" | "outgoing") {
        return Err(invalid("direction must be incoming or outgoing"));
    }

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("function Evidence is required"))?;
    validate_evidence(evidence)
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Select and normalize reference edges from a retained function dossier.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure reference input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .or_else(|| object.get("native_observation"))
        .expect("validated evidence");
    let dossier = result_value(evidence)?;
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("outgoing");
    let references_key = if direction == "incoming" {
        "incoming_references"
    } else {
        "outgoing_references"
    };
    let references = dossier
        .get(references_key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("function Evidence lacks its reference collection"))?;
    if references.len() > MAX_REFERENCES {
        return Err(Failure::new(
            "resource_constraint",
            "resource_constraint",
            "procedure reference output exceeds the reference limit".into(),
            false,
            "Select a narrower procedure or provider result.".into(),
            std::collections::BTreeMap::from([(
                "maximum_references".into(),
                Detail::Count(MAX_REFERENCES as u64),
            )]),
        ));
    }

    let procedure = dossier
        .get("procedure")
        .cloned()
        .ok_or_else(|| invalid("function Evidence lacks procedure identity"))?;
    let unresolved_calls = dossier
        .get("unresolved_calls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let result = json!({
        "procedure": procedure,
        "direction": direction,
        "reference_kinds_available": dossier
            .get("reference_kinds_available")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "unresolved_calls": unresolved_calls,
        // Provider traversal order is part of the retained observation.  Do
        // not sort by endpoint here: duplicate edges and provider-specific
        // classification order are meaningful evidence for callers.
        "references": references,
    });
    validate_result(&result)?;
    Ok(result)
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("function Evidence must be an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some("analyze_function")
        && object.get("operation").and_then(Value::as_str) != Some(OPERATION)
    {
        return Err(invalid(
            "Evidence operation must be analyze_function or procedure_references",
        ));
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("function Evidence must include evidence_id"));
    }
    if !object.contains_key("normalized_result") && !object.contains_key("result") {
        return Err(invalid(
            "function Evidence must include normalized_result or result",
        ));
    }
    let _ = result_value(evidence)?;
    Ok(())
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    let value = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .expect("validated Evidence result");
    let value = value.get("value").unwrap_or(value);
    let dossier = value.get("dossier").unwrap_or(value);
    if !dossier.is_object() || dossier.get("procedure").is_none() {
        return Err(invalid(
            "function Evidence must contain a procedure dossier",
        ));
    }
    Ok(dossier)
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("procedure reference result must be an object"))?;
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("procedure reference result lacks direction"))?;
    if !matches!(direction, "incoming" | "outgoing") {
        return Err(invalid("procedure reference result has invalid direction"));
    }
    if object.get("procedure").is_none()
        || object
            .get("reference_kinds_available")
            .and_then(Value::as_bool)
            .is_none()
        || object.get("references").and_then(Value::as_array).is_none()
        || object
            .get("unresolved_calls")
            .and_then(Value::as_array)
            .is_none()
    {
        return Err(invalid(
            "procedure reference result is missing required fields",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_input",
        "invalid_input",
        message.into(),
        false,
        "Supply a retained function Evidence record and a valid direction.".into(),
        std::collections::BTreeMap::new(),
    )
}
