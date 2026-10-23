//! Evidence projection for provider-specific native pseudocode.
//!
//! Decompilers own the text and its interpretation.  This boundary only
//! authenticates the selected observation and carries its text, identity,
//! locations, and uncertainty into the application workflow.  It never
//! treats pseudocode as source or attempts to regenerate it locally.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "procedure_pseudo_code";
const MAX_PSEUDOCODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_LIMITATIONS: usize = 4_096;
const INPUT_FIELDS: &[&str] = &[
    "evidence",
    "procedure_evidence",
    "function_evidence",
    "procedure",
    "document",
];

/// Project selected provider Evidence into a stable pseudocode result.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let evidence = selected_evidence(input)?;
    project(evidence)
}

/// Validate and project an authenticated `procedure_pseudo_code` Evidence
/// record.  The returned text remains provider output and is never parsed as
/// executable or source code.
pub fn project(evidence: &Value) -> Result<Value, Failure> {
    validate_evidence(evidence)?;

    let result = evidence_result(evidence)?;
    let pseudocode = match result {
        Value::Null => None,
        Value::String(text) => {
            if text.len() > MAX_PSEUDOCODE_BYTES {
                return Err(invalid("pseudocode exceeds the retained byte limit"));
            }
            Some(text.clone())
        }
        _ => {
            return Err(invalid(
                "procedure_pseudo_code result must be a string or null",
            ));
        }
    };

    let evidence_id = required_text(evidence.get("evidence_id"), "evidence_id")?;
    let limitations = bounded_strings(evidence.get("limitations"), "limitations")?;
    let locations = evidence
        .get("locations")
        .or_else(|| evidence.get("selection_locations"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    if !locations.is_array() {
        return Err(invalid("pseudocode locations must be an array"));
    }

    let available = pseudocode.is_some();
    let mut output = json!({
        "pseudocode": pseudocode,
        "available": available,
        "source_evidence_id": evidence_id,
        "limitations": limitations,
        "locations": locations,
    });

    if !available {
        output["reason"] = Value::String(
            limitations
                .first()
                .cloned()
                .unwrap_or_else(|| "The selected provider did not return pseudocode.".into()),
        );
    }

    if let Some(coverage) = evidence
        .get("relationship_coverage")
        .or_else(|| evidence.get("coverage"))
    {
        output["coverage"] = coverage.clone();
    }

    Ok(output)
}

/// Validate an adapter request without resolving or executing a provider.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_pseudo_code input must be an object"))?;
    reject_unknown(object)?;

    let evidence = selected_evidence(input)?;
    validate_evidence(evidence)?;

    if let Some(procedure) = object.get("procedure") {
        let requested = procedure
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("procedure must be a non-empty string"))?;
        let retained = selection_value(evidence, "procedure")
            .ok_or_else(|| invalid("pseudocode Evidence does not identify a procedure"))?;
        if retained != requested {
            return Err(invalid(
                "procedure does not match retained pseudocode Evidence",
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

fn selected_evidence(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_pseudo_code input must be an object"))?;
    object
        .get("evidence")
        .or_else(|| object.get("procedure_evidence"))
        .or_else(|| object.get("function_evidence"))
        .ok_or_else(|| invalid("procedure_pseudo_code requires selected Evidence"))
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    if evidence.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid(
            "selected Evidence is not procedure_pseudo_code Evidence",
        ));
    }
    required_text(evidence.get("evidence_id"), "evidence_id")?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("pseudocode Evidence is missing normalized_result"))?;
    if !result.is_null() && !result.is_string() {
        return Err(invalid(
            "pseudocode Evidence result must be a string or null",
        ));
    }
    if let Value::String(text) = result {
        if text.len() > MAX_PSEUDOCODE_BYTES {
            return Err(invalid("pseudocode exceeds the retained byte limit"));
        }
    }
    bounded_strings(evidence.get("limitations"), "limitations")?;
    Ok(())
}

fn evidence_result(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("pseudocode Evidence is missing normalized_result"))
}

fn bounded_strings(value: Option<&Value>, label: &str) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if values.len() > MAX_LIMITATIONS {
        return Err(invalid(&format!("{label} exceeds the retained item limit")));
    }
    values
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{label} must contain strings")))
        })
        .collect()
}

fn required_text(value: Option<&Value>, label: &str) -> Result<String, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{label} must be non-empty text")))
}

fn selection_value<'a>(evidence: &'a Value, field: &str) -> Option<&'a str> {
    evidence
        .get("selection")
        .and_then(Value::as_object)
        .and_then(|selection| selection.get(field))
        .and_then(Value::as_str)
        .or_else(|| evidence.get(field).and_then(Value::as_str))
}

fn reject_unknown(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown procedure pseudocode input field: {field}"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated procedure_pseudo_code Evidence and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
