//! Read-only projection of a provider-resolved procedure address.
//!
//! Providers own procedure lookup and address interpretation. This module
//! validates a retained observation and returns the exact address text; it
//! does not canonicalize address spaces or reopen a provider database.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "procedure_address";

const INPUT_FIELDS: &[&str] = &[
    "document",
    "evidence",
    "native_observation",
    "procedure",
    "procedure_address",
];

/// Validate a caller-selected retained procedure-address observation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_address input must be an object"))?;
    reject_unknown_fields(object)?;

    let evidence = selected_evidence(object)?;
    validate_evidence(evidence)?;

    if let Some(procedure) = object.get("procedure") {
        let procedure = procedure
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("procedure must be a non-empty string"))?;
        if let Some(retained) = retained_procedure(evidence)
            && retained != procedure
        {
            return Err(invalid(
                "procedure does not match retained procedure-address Evidence",
            ));
        }
    }

    if let Some(document) = object.get("document")
        && !document.is_null()
        && document
            .as_str()
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(invalid("document must be null or a non-empty string"));
    }

    Ok(())
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_address(&result)?;
    Ok(result)
}

/// Return the exact address retained in caller-supplied Evidence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_address input must be an object"))?;
    let evidence = selected_evidence(object)?;
    let address = evidence_address(evidence)?;
    Ok(Value::String(address.to_owned()))
}

/// Alias used by operation-oriented application adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Alias used by adapters that expose resolution by name.
pub fn resolve(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn selected_evidence<'a>(object: &'a serde_json::Map<String, Value>) -> Result<&'a Value, Failure> {
    object
        .get("evidence")
        .or_else(|| object.get("procedure_address"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("procedure_address Evidence is required"))
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("procedure_address Evidence must be an object"))?;

    if let Some(operation) = object.get("operation").and_then(Value::as_str)
        && !matches!(
            operation,
            "procedure_address" | "analyze_function" | "list_procedures" | "search_procedures"
        )
    {
        return Err(invalid(
            "Evidence operation is not a procedure-address observation",
        ));
    }

    required_non_empty_text(object.get("evidence_id"), "evidence_id")?;
    validate_optional_string_array(object.get("limitations"), "limitations")?;
    validate_optional_string_array(object.get("unknowns"), "unknowns")?;
    validate_address(evidence_address_value(evidence)?)
}

fn evidence_address(evidence: &Value) -> Result<&str, Failure> {
    evidence_address_value(evidence)?
        .as_str()
        .ok_or_else(|| invalid("procedure_address Evidence address must be a non-empty string"))
}

fn evidence_address_value(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence);

    if result.is_string() {
        return Ok(result);
    }

    result
        .get("address")
        .or_else(|| result.pointer("/procedure/address"))
        .or_else(|| result.pointer("/dossier/procedure/address"))
        .ok_or_else(|| invalid("procedure_address Evidence has no address result"))
}

fn retained_procedure(evidence: &Value) -> Option<&str> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence);
    result
        .get("procedure")
        .and_then(Value::as_str)
        .or_else(|| {
            result
                .pointer("/selection/procedure")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            result
                .pointer("/dossier/procedure/name")
                .and_then(Value::as_str)
        })
        .or_else(|| evidence.get("procedure").and_then(Value::as_str))
}

fn validate_address(value: &Value) -> Result<(), Failure> {
    let address = value
        .as_str()
        .filter(|address| !address.is_empty())
        .ok_or_else(|| invalid("procedure_address result must be a non-empty string"))?;

    if is_native_address_input(address) {
        Ok(())
    } else {
        Err(invalid(
            "procedure_address result must be a hexadecimal address",
        ))
    }
}

/// Match the TypeScript native-address input grammar without rewriting the
/// caller's spelling.  Canonicalization belongs to consumers that need it;
/// retained Evidence must continue to expose the provider's exact value.
fn is_native_address_input(value: &str) -> bool {
    let (space, digits) = match value.split_once(':') {
        Some((space, digits)) => (Some(space), digits),
        None => (None, value),
    };

    if let Some(space) = space {
        if space.is_empty() || !is_address_space(space) {
            return false;
        }
    }

    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"));
    let Some(digits) = digits else {
        return false;
    };

    !digits.is_empty()
        && digits
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn is_address_space(value: &str) -> bool {
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character.is_ascii_alphanumeric() || "._~-".contains(character) {
            continue;
        }

        if character != '%' {
            return false;
        }

        let Some(first) = characters.next() else {
            return false;
        };
        let Some(second) = characters.next() else {
            return false;
        };
        if !first.is_ascii_hexdigit() || !second.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}

fn required_non_empty_text(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .is_some()
    {
        Ok(())
    } else {
        Err(invalid(&format!("Evidence must include non-empty {field}")))
    }
}

fn validate_optional_string_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let Some(items) = value else {
        return Ok(());
    };
    let items = items
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if items.len() > 4_096 {
        return Err(invalid(&format!("{field} exceeds the retained item limit")));
    }
    if items.iter().any(|item| !item.is_string()) {
        return Err(invalid(&format!("{field} must contain strings")));
    }
    Ok(())
}

fn reject_unknown_fields(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown procedure_address input field: {field}"
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
        "Provide retained procedure_address Evidence and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
