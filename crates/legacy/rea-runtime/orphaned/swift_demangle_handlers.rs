//! Offline handler for the exact `demangle_swift` operation.
//!
//! This boundary accepts only caller-supplied symbols and captured
//! `swift-demangle` output, or an authenticated Evidence record. It never
//! resolves or launches `swift-demangle`; line parsing remains owned by the
//! application producer.

use rea_application::native::swift_demangle;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = swift_demangle::OPERATION;

/// The single exact-name operation owned by this handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    DemangleSwift,
}

impl Operation {
    /// Parse the public operation name and reject aliases.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            OPERATION => Ok(Self::DemangleSwift),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical contract operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DemangleSwift => OPERATION,
        }
    }
}

/// Dispatch one captured Swift demangling request by public operation name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = Operation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch a previously parsed operation without contacting a host tool.
pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::DemangleSwift => demangle_swift(input),
    }
}

/// Handle the exact `demangle_swift` contract from captured values only.
pub fn demangle_swift(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    if object.contains_key("evidence_id") {
        return project_evidence(input);
    }

    reject_unknown_fields(object)?;

    let symbols = required_symbols(object)?;
    let stdout = object
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("stdout is required"))?;
    let provenance = object
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let limitations = optional_string_array(object, "limitations")?;

    swift_demangle::result(&symbols, stdout, provenance, limitations)
        .map_err(|reason| invalid(&reason))
}

fn required_symbols(object: &Map<String, Value>) -> Result<Vec<String>, Failure> {
    let symbols = object
        .get("symbols")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("symbols is required and must be an array"))?;

    symbols
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("symbols must contain strings"))
        })
        .collect()
}

fn optional_string_array(
    object: &Map<String, Value>,
    field: &str,
) -> Result<Vec<String>, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| invalid(&format!("{field} must be an array")))?
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| invalid(&format!("{field} must contain strings")))
                })
                .collect()
        })
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: [&str; 4] = ["symbols", "stdout", "provenance", "limitations"];
    if object
        .keys()
        .any(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(&format!("Evidence is not valid JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("Evidence operation does not match demangle_swift"));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is invalid JSON: {error}")))?;
    validate_projected_result(&result)?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

fn validate_projected_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| integrity("Evidence result must be an object"))?;

    for field in ["symbols", "provenance", "limitations"] {
        if !object.contains_key(field) {
            return Err(integrity(&format!(
                "Evidence result is missing the {field} field"
            )));
        }
    }

    if object.keys().any(|field| {
        !matches!(field.as_str(), "symbols" | "provenance" | "limitations")
    }) {
        return Err(integrity("Evidence result contains an unknown field"));
    }

    if !object
        .get("symbols")
        .and_then(Value::as_array)
        .is_some()
    {
        return Err(integrity("Evidence symbols must be an array"));
    }
    if !object
        .get("provenance")
        .and_then(Value::as_array)
        .is_some()
    {
        return Err(integrity("Evidence provenance must be an array"));
    }
    if !object
        .get("limitations")
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().all(Value::is_string))
    {
        return Err(integrity(
            "Evidence limitations must be an array of strings",
        ));
    }

    let symbols = object
        .get("symbols")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity("Evidence symbols must be an array"))?;
    for symbol in symbols {
        let symbol = symbol
            .as_object()
            .ok_or_else(|| integrity("Evidence symbol must be an object"))?;
        if symbol.keys().any(|field| {
            !matches!(field.as_str(), "input" | "output" | "status")
        }) {
            return Err(integrity("Evidence symbol contains an unknown field"));
        }
        if !symbol
            .get("input")
            .and_then(Value::as_str)
            .is_some()
            || !symbol
                .get("output")
                .and_then(Value::as_str)
                .is_some()
            || !symbol
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| {
                    matches!(status, "demangled" | "unchanged" | "invalid")
                })
        {
            return Err(integrity("Evidence symbol has an invalid shape"));
        }
    }

    Ok(())
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Swift demangling operation is unknown: {name}"),
        false,
        "Select demangle_swift with caller-supplied captured output or Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide symbols with bounded caller-supplied swift-demangle output or authenticated Evidence; the runtime does not launch swift-demangle.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide authenticated, intact demangle_swift Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
