//! Read-only projection of retained string inventory Evidence.
//!
//! Providers own string discovery and byte decoding.  This boundary only
//! validates already retained rows and applies the optional exact-address
//! selector; it never opens a provider database or reads the target again.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_strings";

const MAX_ROWS: usize = 200_000;
const INPUT_FIELDS: &[&str] = &[
    "address",
    "document",
    "evidence",
    "inventory",
    "native_observation",
    "observations",
    "strings",
];
const ROW_FIELDS: &[&str] = &["address", "decoding", "provider_value", "string", "value"];

/// Validate a caller request and every supplied retained observation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_strings input must be an object"))?;
    reject_unknown_fields(object)?;

    if let Some(address) = object.get("address") {
        require_non_empty_string(Some(address), "address")?;
    }
    if let Some(document) = object.get("document") {
        require_non_empty_string(Some(document), "document")?;
    }

    if let Some(strings) = object.get("strings").or_else(|| object.get("inventory")) {
        validate_rows(Some(strings), "string inventory")?;
    }
    if let Some(evidence) = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
    {
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

    if !has_inventory_source(object) {
        return Err(invalid(
            "list_strings requires retained string inventory Evidence",
        ));
    }

    Ok(())
}

/// Return all retained rows, or rows at one exact address.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    let object = input
        .as_object()
        .expect("validated list_strings input object");
    let rows = resolve_rows(object)?;
    let selected = match object.get("address").and_then(Value::as_str) {
        Some(address) => rows
            .into_iter()
            .filter(|row| row.get("address").and_then(Value::as_str) == Some(address))
            .collect(),
        None => rows,
    };

    Ok(Value::Array(selected))
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_rows(Some(&result), "list_strings result")?;
    Ok(result)
}

/// Alias used by adapters that name the operation after its result shape.
pub fn list(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Alias used by retained-Evidence inspection adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn resolve_rows(object: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let mut rows = Vec::new();
    if let Some(strings) = object.get("strings").or_else(|| object.get("inventory")) {
        append_rows(strings, &mut rows, "string inventory")?;
    }
    if let Some(evidence) = object
        .get("evidence")
        .or_else(|| object.get("native_observation"))
    {
        append_evidence_rows(evidence, &mut rows)?;
    }
    if let Some(observations) = object.get("observations").and_then(Value::as_array) {
        for observation in observations {
            append_evidence_rows(observation, &mut rows)?;
        }
    }
    if rows.is_empty() && !object.contains_key("strings") && !object.contains_key("inventory") {
        return Err(invalid(
            "list_strings requires retained string inventory Evidence",
        ));
    }
    Ok(rows)
}

fn append_evidence_rows(evidence: &Value, rows: &mut Vec<Value>) -> Result<(), Failure> {
    let values = rows_from_evidence(evidence)?;
    append_values(values, rows, "string Evidence")
}

fn append_rows(value: &Value, rows: &mut Vec<Value>, label: &str) -> Result<(), Failure> {
    let values = rows_from_value(value, label)?;
    append_values(values, rows, label)
}

fn append_values(values: Vec<Value>, rows: &mut Vec<Value>, label: &str) -> Result<(), Failure> {
    if rows.len().saturating_add(values.len()) > MAX_ROWS {
        return Err(invalid(&format!("{label} exceeds the 200000 record limit")));
    }
    rows.extend(values);
    Ok(())
}

fn rows_from_evidence(evidence: &Value) -> Result<Vec<Value>, Failure> {
    validate_evidence(evidence)?;
    let result = result_value(evidence)?;

    if let Some(referenced) = result.pointer("/dossier/referenced_strings") {
        return rows_from_value(referenced, "Evidence referenced strings");
    }
    rows_from_value(result, "Evidence string inventory")
}

fn rows_from_value(value: &Value, label: &str) -> Result<Vec<Value>, Failure> {
    if let Some(items) = value.get("items") {
        return rows_from_value(items, label);
    }
    if let Some(strings) = value.get("strings") {
        return rows_from_value(strings, label);
    }
    if let Some(value) = value.get("value") {
        return rows_from_value(value, label);
    }
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    validate_rows(Some(value), label)?;
    Ok(rows.clone())
}

fn validate_rows(value: Option<&Value>, label: &str) -> Result<(), Failure> {
    let rows = value
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?
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
    if let Some(field) = object
        .keys()
        .find(|field| !ROW_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!("{label} contains unknown field {field}")));
    }
    require_non_empty_string(object.get("address"), &format!("{label}.address"))?;
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .expect("validated string inventory address");
    if !is_canonical_address(address) {
        return Err(invalid(&format!(
            "{label}.address must be a canonical address"
        )));
    }
    require_string(object.get("value"), &format!("{label}.value"))?;

    if let Some(provider_value) = object.get("provider_value") {
        require_string(Some(provider_value), &format!("{label}.provider_value"))?;
    }
    if let Some(decoding) = object.get("decoding") {
        validate_decoding(decoding, label)?;
    }
    if let Some(string) = object.get("string") {
        validate_string_facts(string, label)?;
    }

    Ok(())
}

fn validate_decoding(value: &Value, label: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label}.decoding must be an object")))?;
    if object
        .keys()
        .any(|key| key != "available" && key != "reason")
    {
        return Err(invalid(&format!(
            "{label}.decoding contains unknown fields"
        )));
    }
    if object.get("available") != Some(&Value::Bool(false)) {
        return Err(invalid(&format!(
            "{label}.decoding.available must be false"
        )));
    }
    require_string(object.get("reason"), &format!("{label}.decoding.reason"))
}

fn validate_string_facts(value: &Value, label: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("{label}.string must be an object")))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "byte_length" | "encoding" | "encoding_status" | "termination"
        )
    }) {
        return Err(invalid(&format!("{label}.string contains unknown fields")));
    }
    require_non_empty_string(object.get("encoding"), &format!("{label}.string.encoding"))?;
    require_string(
        object.get("termination"),
        &format!("{label}.string.termination"),
    )?;
    if !matches!(
        object.get("termination").and_then(Value::as_str),
        Some("missing" | "present_or_not_required")
    ) {
        return Err(invalid(&format!("{label}.string.termination is invalid")));
    }
    if let Some(status) = object.get("encoding_status") {
        if !matches!(status.as_str(), Some("observed") | Some("inferred")) {
            return Err(invalid(&format!(
                "{label}.string.encoding_status is invalid"
            )));
        }
    }
    if object.get("byte_length").and_then(Value::as_u64).is_none() {
        return Err(invalid(&format!(
            "{label}.string.byte_length must be non-negative"
        )));
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("list_strings Evidence must be an object"))?;
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("list_strings Evidence must include evidence_id"));
    }
    if let Some(operation) = object.get("operation").and_then(Value::as_str) {
        if !matches!(
            operation,
            "list_strings" | "search_strings" | "analyze_function"
        ) {
            return Err(invalid("Evidence does not contain string observations"));
        }
    }
    let _ = result_value(evidence)?;
    Ok(())
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .ok_or_else(|| invalid("string Evidence has no normalized result"))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown list_strings input field: {field}"
        )));
    }
    Ok(())
}

fn has_inventory_source(object: &Map<String, Value>) -> bool {
    object.contains_key("strings")
        || object.contains_key("inventory")
        || object.contains_key("evidence")
        || object.contains_key("native_observation")
        || object.contains_key("observations")
}

fn require_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{field} must be a string")));
    }
    Ok(())
}

fn require_non_empty_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).is_none_or(str::is_empty) {
        return Err(invalid(&format!("{field} must be a non-empty string")));
    }
    Ok(())
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

fn valid_percent_escape(value: &str, index: usize) -> bool {
    let bytes = value.as_bytes();
    index + 2 < bytes.len()
        && is_upper_hex_digit(bytes[index + 1])
        && is_upper_hex_digit(bytes[index + 2])
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_upper_hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'A'..=b'F')
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained list_strings Evidence or a bounded string inventory.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
