//! Static name-to-reference projection for the native analysis boundary.
//!
//! The historical enhanced operation composes two provider operations: it
//! resolves an exact name from `list_names`, then asks `xrefs` for the
//! resolved address.  This module keeps that interpretation at the boundary
//! while accepting only already retained observations.  It never opens a
//! provider database or performs a live lookup.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "find_xrefs_to_name";

const NAME_FIELDS: &[&str] = &[
    "name",
    "names",
    "evidence",
    "name_evidence",
    "name_observation",
    "xrefs",
    "xref_evidence",
    "xref_observation",
];

/// Validate a native projection request and all supplied source observations.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("find-xrefs input must be an object"))?;

    for key in object.keys() {
        if !NAME_FIELDS.contains(&key.as_str()) {
            return Err(invalid(&format!("unknown find-xrefs input field: {key}")));
        }
    }

    if object.get("name").and_then(Value::as_str).is_none() {
        return Err(invalid("find-xrefs input requires a string name"));
    }

    if let Some(names) = object.get("names") {
        parse_names(names)?;
    }
    if let Some(evidence) = object
        .get("name_evidence")
        .or_else(|| object.get("name_observation"))
    {
        parse_name_evidence(evidence)?;
    }
    if let Some(xrefs) = object.get("xrefs") {
        parse_xrefs(xrefs)?;
    }
    if let Some(evidence) = object
        .get("xref_evidence")
        .or_else(|| object.get("xref_observation"))
    {
        parse_xref_evidence(evidence)?;
    }
    if let Some(evidence) = object.get("evidence") {
        validate_generic_evidence(evidence)?;
    }

    Ok(())
}

/// Resolve an exact name against supplied inventory and xref observations.
pub fn find(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("find-xrefs input must be an object"))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("find-xrefs input requires a string name"))?;

    let names = resolve_names(object)?;
    let Some(resolved) = names.iter().find(|entry| entry.name == name) else {
        return Ok(json!({
            "status": "unresolved",
            "name": name,
            "reason": "name_not_found"
        }));
    };

    let xrefs = resolve_xrefs(object)?;
    let result = json!({
        "status": "resolved",
        "name": name,
        "address": resolved.address,
        "xrefs": xrefs,
    });
    validate_result(&result)?;
    Ok(result)
}

/// Alias matching the operation-oriented naming used by other producers.
pub fn resolve(input: &Value) -> Result<Value, Failure> {
    find(input)
}

/// Validate a provider result before the runtime wraps it as Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

#[derive(Clone)]
struct NameEntry {
    address: String,
    name: String,
}

fn resolve_names(object: &serde_json::Map<String, Value>) -> Result<Vec<NameEntry>, Failure> {
    if let Some(names) = object.get("names") {
        return parse_names(names);
    }
    if let Some(evidence) = object
        .get("name_evidence")
        .or_else(|| object.get("name_observation"))
    {
        return parse_name_evidence(evidence);
    }
    if let Some(evidence) = object.get("evidence") {
        return parse_name_evidence(evidence);
    }
    Err(invalid(
        "find-xrefs requires retained name inventory Evidence",
    ))
}

fn resolve_xrefs(object: &serde_json::Map<String, Value>) -> Result<Vec<String>, Failure> {
    if let Some(xrefs) = object.get("xrefs") {
        return parse_xrefs(xrefs);
    }
    if let Some(evidence) = object
        .get("xref_evidence")
        .or_else(|| object.get("xref_observation"))
    {
        return parse_xref_evidence(evidence);
    }
    if let Some(evidence) = object.get("evidence") {
        return parse_xref_evidence(evidence);
    }
    Err(invalid("find-xrefs requires retained xref Evidence"))
}

fn parse_name_evidence(evidence: &Value) -> Result<Vec<NameEntry>, Failure> {
    validate_generic_evidence(evidence)?;
    let result = result_value(evidence);
    let names = result
        .get("names")
        .or_else(|| result.get("items"))
        .or_else(|| result.get("value"))
        .unwrap_or(result);
    parse_names(names)
}

fn parse_names(value: &Value) -> Result<Vec<NameEntry>, Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("name inventory must be an array"))?;
    if values.len() > 200_000 {
        return Err(invalid("name inventory exceeds the 200000 record limit"));
    }
    values.iter().map(parse_name_entry).collect()
}

fn parse_name_entry(value: &Value) -> Result<NameEntry, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("name inventory entry must be an object"))?;
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("name inventory entry requires a non-empty address"))?;
    let name = object
        .get("name")
        .or_else(|| object.get("value"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("name inventory entry requires a string name"))?;
    Ok(NameEntry {
        address: address.to_owned(),
        name: name.to_owned(),
    })
}

fn parse_xref_evidence(evidence: &Value) -> Result<Vec<String>, Failure> {
    validate_generic_evidence(evidence)?;
    parse_xrefs(result_value(evidence))
}

fn parse_xrefs(value: &Value) -> Result<Vec<String>, Failure> {
    let values = value
        .get("xrefs")
        .or_else(|| value.get("references"))
        .or_else(|| value.get("result"))
        .unwrap_or(value);
    let values = values
        .as_array()
        .ok_or_else(|| invalid("xref observation must be an address array"))?;
    if values.len() > 200_000 {
        return Err(invalid("xref observation exceeds the 200000 record limit"));
    }
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("xref observation entries must be strings"))
        })
        .collect()
}

fn result_value(evidence: &Value) -> &Value {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .unwrap_or(evidence)
}

fn validate_generic_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("source Evidence must be an object"))?;
    if let Some(id) = object.get("evidence_id")
        && (!id.is_string() || id.as_str().is_some_and(str::is_empty))
    {
        return Err(invalid(
            "source Evidence evidence_id must be a non-empty string",
        ));
    }
    if let Some(operation) = object.get("operation")
        && operation.as_str().is_none()
    {
        return Err(invalid("source Evidence operation must be a string"));
    }
    Ok(())
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("find-xrefs result must be an object"))?;
    match object.get("status").and_then(Value::as_str) {
        Some("unresolved") => {
            if object.get("name").and_then(Value::as_str).is_none()
                || object.get("reason").and_then(Value::as_str) != Some("name_not_found")
            {
                return Err(invalid("unresolved find-xrefs result has invalid fields"));
            }
        }
        Some("resolved") => {
            if object.get("name").and_then(Value::as_str).is_none()
                || object.get("address").and_then(Value::as_str).is_none()
            {
                return Err(invalid("resolved find-xrefs result has invalid identity"));
            }
            let xrefs = object
                .get("xrefs")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("resolved find-xrefs result requires xrefs"))?;
            if xrefs.len() > 200_000 || xrefs.iter().any(|xref| xref.as_str().is_none()) {
                return Err(invalid("resolved find-xrefs result has invalid xrefs"));
            }
        }
        _ => return Err(invalid("find-xrefs result status is invalid")),
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained list_names and xrefs Evidence for an exact name projection.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
