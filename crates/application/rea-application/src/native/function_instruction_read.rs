//! Projection of a provider's complete instruction window for one function.
//!
//! Instruction decoding belongs to the provider boundary.  This module only
//! validates and projects authenticated Evidence, so a missing or undecodable
//! instruction remains represented by the provider's original text and
//! limitations rather than being reconstructed from bytes here.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "read_function_instructions";

const MAX_INSTRUCTIONS: usize = 200_000;
const MAX_TEXT_BYTES: usize = 32 * 1024 * 1024;

/// Validate a caller-selected function instruction request and its Evidence.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("function instruction input must be an object"))?;

    reject_unknown_fields(
        object,
        &[
            "evidence",
            "function",
            "analysis",
            "procedure",
            "address",
            "offset",
            "limit",
        ],
        "function instruction input",
    )?;

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .or_else(|| object.get("analysis"))
        .ok_or_else(|| invalid("function instruction Evidence is required"))?;
    validate_evidence(evidence)?;

    let result = result_value(evidence)?;
    if let Some(procedure) = object.get("procedure") {
        let requested = procedure
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("procedure must be a non-empty string"))?;
        let actual = result
            .get("procedure")
            .and_then(|value| value.get("name"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("instruction result is missing procedure.name"))?;
        if requested != actual {
            return Err(invalid(
                "procedure does not match retained instruction Evidence",
            ));
        }
    }

    if let Some(address) = object.get("address") {
        let requested = address
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("address must be a non-empty string"))?;
        let actual = result
            .get("procedure")
            .and_then(|value| value.get("address"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("instruction result is missing procedure.address"))?;
        if requested != actual {
            return Err(invalid(
                "address does not match retained instruction Evidence",
            ));
        }
    }

    validate_optional_limit(object.get("offset"), "offset")?;
    validate_optional_limit(object.get("limit"), "limit")?;
    Ok(())
}

/// Validate a provider result before the runtime stores it as Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Return the authenticated instruction-window result without contacting a
/// provider or opening a binary database.
pub fn read(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    Ok(result_value(
        input
            .as_object()
            .and_then(|object| {
                object
                    .get("evidence")
                    .or_else(|| object.get("function"))
                    .or_else(|| object.get("analysis"))
            })
            .ok_or_else(|| invalid("function instruction Evidence is required"))?,
    )?
    .clone())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("function instruction Evidence must be an object"))?;
    if let Some(operation) = object.get("operation") {
        if operation.as_str() != Some(OPERATION) {
            return Err(invalid(
                "Evidence operation is not read_function_instructions",
            ));
        }
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid(
            "function instruction Evidence must include evidence_id",
        ));
    }
    validate_result(result_value(evidence)?)
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .unwrap_or(evidence);
    if !result.is_object() {
        return Err(invalid("function instruction result must be an object"));
    }
    Ok(result)
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("function instruction result must be an object"))?;
    reject_unknown_fields(
        object,
        &["procedure", "instructions", "limitations"],
        "instruction result",
    )?;
    validate_procedure(object.get("procedure"))?;

    let instructions = object
        .get("instructions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("instructions must be an array"))?;
    if instructions.len() > MAX_INSTRUCTIONS {
        return Err(invalid("instruction window exceeds the record limit"));
    }
    let mut text_bytes = 0usize;
    for instruction in instructions {
        let text = instruction
            .as_str()
            .ok_or_else(|| invalid("instruction entries must be strings"))?;
        text_bytes = text_bytes
            .checked_add(text.len())
            .ok_or_else(|| invalid("instruction text size overflow"))?;
        if text_bytes > MAX_TEXT_BYTES {
            return Err(invalid("instruction window exceeds the text limit"));
        }
    }
    validate_string_array(object.get("limitations"), "limitations")
}

fn validate_procedure(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("procedure must be an object"))?;
    require_non_empty_text(object.get("address"), "procedure.address")?;
    require_text(object.get("name"), "procedure.name")?;

    // The provider-neutral schema requires these fields.  Their nested body
    // is owned by the function identity schema, so validate its shape when it
    // is present while retaining the complete original object unchanged.
    if let Some(classification) = object.get("classification") {
        if !classification.is_null() {
            let classification = classification
                .as_object()
                .ok_or_else(|| invalid("procedure.classification must be an object or null"))?;
            reject_unknown_fields(
                classification,
                &["external", "thunk", "thunk_target", "provenance"],
                "procedure.classification",
            )?;
            require_bool(
                classification.get("external"),
                "procedure.classification.external",
            )?;
            require_bool(
                classification.get("thunk"),
                "procedure.classification.thunk",
            )?;
            require_nullable_text(
                classification.get("thunk_target"),
                "procedure.classification.thunk_target",
            )?;
            require_non_empty_text(
                classification.get("provenance"),
                "procedure.classification.provenance",
            )?;
        }
    }
    Ok(())
}

fn validate_optional_limit(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        let number = value
            .as_u64()
            .ok_or_else(|| invalid(&format!("{name} must be a non-negative integer")))?;
        if number as usize > MAX_INSTRUCTIONS {
            return Err(invalid(&format!("{name} exceeds the instruction limit")));
        }
    }
    Ok(())
}

fn validate_string_array(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{name} must be an array")))?;
    if values.len() > MAX_INSTRUCTIONS {
        return Err(invalid(&format!("{name} exceeds the record limit")));
    }
    if values.iter().any(|value| value.as_str().is_none()) {
        return Err(invalid(&format!("{name} entries must be strings")));
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), Failure> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(invalid(&format!(
            "{context} contains unknown field {field}"
        )));
    }
    Ok(())
}

fn require_text(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{name} must be a string")));
    }
    Ok(())
}

fn require_non_empty_text(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    if value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .is_none()
    {
        return Err(invalid(&format!("{name} must be a non-empty string")));
    }
    Ok(())
}

fn require_nullable_text(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    match value {
        Some(value) if value.is_null() || value.as_str().is_some() => Ok(()),
        _ => Err(invalid(&format!("{name} must be a string or null"))),
    }
}

fn require_bool(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_bool).is_none() {
        return Err(invalid(&format!("{name} must be a boolean")));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        false,
        "Provide retained read_function_instructions Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
