//! Read-only projection of retained procedure inventory Evidence.
//!
//! Providers own procedure discovery and metadata decoding.  This module only
//! validates the bounded rows supplied by an adapter and projects them without
//! sorting, deduplicating, or reconstructing provider facts.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_procedures";
const MAX_ROWS: usize = 200_000;

/// Validate a direct inventory request or a request carrying retained rows.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_procedures input must be an object"))?;

    reject_unknown_fields(object)?;
    validate_document(object.get("document"))?;

    if let Some(procedures) = object.get("procedures") {
        validate_rows(procedures, "procedures")?;
    }

    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence)?;
    }

    if let Some(observations) = object.get("observations") {
        let observations = observations
            .as_array()
            .ok_or_else(|| invalid("observations must be an array"))?;
        if observations.len() > MAX_ROWS {
            return Err(invalid("observations exceed the 200000 record limit"));
        }
        for observation in observations {
            validate_evidence(observation)?;
        }
    }

    Ok(())
}

/// Return retained procedure rows in their source order.
pub fn list(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    let object = input
        .as_object()
        .expect("list_procedures input was validated as an object");
    let mut rows = Vec::new();

    if let Some(procedures) = object.get("procedures") {
        append_rows(procedures, &mut rows, "procedures")?;
    }
    if let Some(evidence) = object.get("evidence") {
        append_evidence_rows(evidence, &mut rows)?;
    }
    if let Some(observations) = object.get("observations").and_then(Value::as_array) {
        for observation in observations {
            append_evidence_rows(observation, &mut rows)?;
        }
    }

    if object.get("procedures").is_none()
        && object.get("evidence").is_none()
        && object.get("observations").is_none()
    {
        return Err(invalid("a retained procedure inventory is required"));
    }

    Ok(Value::Array(rows))
}

/// Inspect is the application-layer name used by retained Evidence callers.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    list(input)
}

/// Project a retained procedure inventory without changing its row order.
pub fn project(input: &Value) -> Result<Value, Failure> {
    list(input)
}

/// Validate a provider result before it is retained as Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_rows(&result, "result")?;
    Ok(result)
}

fn append_evidence_rows(evidence: &Value, rows: &mut Vec<Value>) -> Result<(), Failure> {
    validate_evidence(evidence)?;
    let result = evidence_result(evidence);

    if result.is_array() {
        append_rows(result, rows, "procedure Evidence result")?;
    } else if let Some(items) = result.get("items") {
        append_rows(items, rows, "procedure Evidence items")?;
    } else {
        return Err(invalid("procedure Evidence result must be an array"));
    }

    Ok(())
}

fn append_rows(value: &Value, rows: &mut Vec<Value>, label: &str) -> Result<(), Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    validate_rows(value, label)?;

    if rows.len().saturating_add(values.len()) > MAX_ROWS {
        return Err(invalid(
            "procedure inventory exceeds the 200000 record limit",
        ));
    }
    rows.extend(values.iter().cloned());
    Ok(())
}

fn validate_rows(value: &Value, label: &str) -> Result<(), Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(&format!("{label} exceeds the 200000 record limit")));
    }
    for (index, row) in rows.iter().enumerate() {
        validate_row(row, &format!("{label}[{index}]"))?;
    }
    Ok(())
}

fn validate_row(value: &Value, label: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label} must be an object")))?;
    reject_row_fields(object, label)?;

    if object
        .get("address")
        .and_then(Value::as_str)
        .is_none_or(|address| !is_canonical_address(address))
    {
        return Err(invalid(&format!(
            "{label}.address must be a canonical address"
        )));
    }
    if object.get("value").and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{label}.value must be a string")));
    }

    let procedure = object
        .get("procedure")
        .ok_or_else(|| invalid(&format!("{label}.procedure is required")))?;
    validate_procedure_facts(procedure, label)
}

fn validate_procedure_facts(value: &Value, label: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label}.procedure must be an object")))?;
    reject_fields(object, &["external", "thunk", "thunk_target"], label)?;
    if !object.get("external").is_some_and(Value::is_boolean)
        || !object.get("thunk").is_some_and(Value::is_boolean)
        || !object.get("thunk_target").is_some_and(|value| {
            value.is_null() || value.as_str().is_some_and(is_canonical_address)
        })
    {
        return Err(invalid(&format!("{label}.procedure has invalid facts")));
    }
    Ok(())
}

fn validate_evidence(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("procedure Evidence must be an object"))?;
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid("procedure Evidence must include evidence_id"));
    }
    if let Some(operation) = object.get("operation") {
        if operation.as_str() != Some(OPERATION) {
            return Err(invalid("Evidence operation is not list_procedures"));
        }
    }
    let result = evidence_result(value);
    if !result.is_array() && result.get("items").is_none() {
        return Err(invalid("procedure Evidence result must be an array"));
    }
    Ok(())
}

fn evidence_result(evidence: &Value) -> &Value {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence)
}

fn validate_document(value: Option<&Value>) -> Result<(), Failure> {
    if let Some(document) = value {
        if !document.is_null() && document.as_str().is_none_or(str::is_empty) {
            return Err(invalid("document must be a non-empty string or null"));
        }
    }
    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    reject_fields(
        object,
        &["document", "procedures", "evidence", "observations"],
        "input",
    )
}

fn reject_row_fields(object: &Map<String, Value>, label: &str) -> Result<(), Failure> {
    reject_fields(object, &["address", "value", "procedure"], label)
}

fn is_canonical_address(address: &str) -> bool {
    let Some((space, offset)) = address.split_once(':') else {
        return address.starts_with("0x") && is_lower_hex(&address[2..]);
    };

    !space.is_empty()
        && space.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b'-')
                || (byte == b'%' && valid_percent_escape(space, index))
        })
        && offset.starts_with("0x")
        && is_lower_hex(&offset[2..])
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_percent_escape(value: &str, index: usize) -> bool {
    let bytes = value.as_bytes();
    index + 2 < bytes.len()
        && is_upper_hex_or_digit(bytes[index + 1])
        && is_upper_hex_or_digit(bytes[index + 2])
}

fn is_upper_hex_or_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn reject_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(&format!("unknown {label} field: {key}")));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        true,
        "Supply a bounded retained procedure inventory and valid procedure rows.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
