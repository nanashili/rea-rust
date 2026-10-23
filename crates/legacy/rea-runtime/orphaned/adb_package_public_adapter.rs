//! Public runtime boundary for retained ADB package observations.
//!
//! The device and APK producers run before this boundary.  This adapter only
//! validates their retained projection and authenticated Evidence, so invoking
//! the public operation cannot contact ADB, open an APK path, or execute code.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_adb_package";

/// Dispatch the public operation using only caller-supplied retained facts.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    project(&input)
}

/// Validate and envelope a retained package projection.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_adb_package input must be an object"))?;
    let result = retained_result(object)?;
    let result_object = result
        .as_object()
        .ok_or_else(|| invalid("inspect_adb_package result must be an object"))?;

    let serial = required_text(result_object, "serial")?;
    let package_name = required_text(result_object, "package_name")?;
    validate_identity(&serial, "serial")?;
    validate_identity(&package_name, "package_name")?;

    let evidence = retained_evidence(object)?;
    validate_evidence(&evidence, &serial, &package_name)?;

    Ok(serde_json::json!({
        "result": result,
        "evidence": evidence,
        "provenance": {
            "operation": OPERATION,
            "source": "caller-supplied-adb-package-facts",
            "execution": "none"
        }
    }))
}

fn retained_result(object: &Map<String, Value>) -> Result<Value, Failure> {
    if let Some(result) = object.get("result") {
        return Ok(result.clone());
    }
    if let Some(projection) = object.get("projection") {
        return Ok(projection.clone());
    }

    Err(invalid(
        "inspect_adb_package retained result or projection is required",
    ))
}

fn retained_evidence(object: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let evidence = object
        .get("evidence")
        .ok_or_else(|| invalid("inspect_adb_package authenticated Evidence is required"))?;

    match evidence {
        Value::Array(records) if !records.is_empty() => Ok(records.clone()),
        Value::Array(_) => Err(invalid("inspect_adb_package Evidence must not be empty")),
        Value::Object(_) => Ok(vec![evidence.clone()]),
        _ => Err(invalid("inspect_adb_package Evidence must be an object or array")),
    }
}

fn validate_evidence(
    evidence: &[Value],
    serial: &str,
    package_name: &str,
) -> Result<(), Failure> {
    let mut evidence_ids = BTreeSet::new();
    for record in evidence {
        let object = record
            .as_object()
            .ok_or_else(|| invalid("package Evidence record must be an object"))?;
        let evidence_id = required_text(object, "evidence_id")?;
        if !evidence_ids.insert(evidence_id) {
            return Err(invalid(
                "package Evidence ids must be unique",
            ));
        }

        let operation = required_text(object, "operation")?;
        if operation != OPERATION {
            return Err(integrity(
                "package Evidence operation does not match inspect_adb_package",
            ));
        }

        if object.get("authenticated") != Some(&Value::Bool(true)) {
            return Err(integrity("package Evidence must be authenticated"));
        }

        if required_text(object, "serial")? != serial
            || required_text(object, "package_name")? != package_name
        {
            return Err(integrity(
                "package Evidence subject does not match the retained package result",
            ));
        }
    }

    Ok(())
}

fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("inspect_adb_package {field} is required")))
}

fn validate_identity(value: &str, field: &str) -> Result<(), Failure> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid(&format!(
            "inspect_adb_package {field} must be between 1 and 256 bytes"
        )));
    }

    if field == "serial" {
        if value.chars().any(|character| {
            character.is_whitespace()
                || character == '\0'
                || character == '"'
                || character == '\''
        }) {
            return Err(invalid(&format!(
                "inspect_adb_package {field} cannot contain whitespace, NUL, or quotes"
            )));
        }
        return Ok(());
    }

    for segment in value.split('.') {
        let mut characters = segment.chars();
        let Some(first) = characters.next() else {
            return Err(invalid(&format!(
                "inspect_adb_package {field} must contain Java identifier segments"
            )));
        };
        if !first.is_ascii_alphabetic()
            || characters.any(|character| !character.is_ascii_alphanumeric() && character != '_')
        {
            return Err(invalid(&format!(
                "inspect_adb_package {field} must be dot-separated Java identifiers"
            )));
        }
    }

    Ok(())
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("ADB package operation is unknown: {operation}"),
        false,
        "Select inspect_adb_package with retained package facts.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a retained ADB package result and authenticated Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide authenticated Evidence for the same serial and package identity.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
