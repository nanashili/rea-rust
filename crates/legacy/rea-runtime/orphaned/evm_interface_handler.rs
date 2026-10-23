//! Retained-report boundary for `inspect_evm_interface`.
//!
//! The normal EVM path owns stable reads and bytecode parsing. This handler is
//! for callers that already possess a complete report. It binds that report
//! to the caller-selected artifact and checks the invariants needed by the
//! downstream Evidence views without re-running analysis.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_evm_interface";
const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024;

/// Project a captured EVM observation without reopening the artifact.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input_object(&input, "input")?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 {
            return Err(invalid("Evidence input cannot be combined with request fields"));
        }
        return project_evidence(evidence);
    }

    handle(&input)
}

/// Validate and return a caller-supplied complete EVM interface report.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = input_object(input, "request")?;
    reject_unknown(request, &["path", "sha256", "report"], "request")?;
    let path = required_path(request)?;
    let digest = required_digest(request.get("sha256"), "sha256")?;
    let report = request
        .get("report")
        .ok_or_else(|| invalid("report is required"))?;

    validate_report(report, path, digest)?;

    Ok(report.clone())
}

fn project_evidence(evidence: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("evidence could not be encoded: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "evidence operation must be inspect_evm_interface",
        ));
    }

    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("EVM Evidence normalized_result is invalid JSON: {error}")))?;
    let report = normalized
        .as_object()
        .ok_or_else(|| invalid("EVM Evidence normalized_result must be an object"))?;
    let artifact = required_object(report, "artifact")?;
    let path = required_text(artifact, "path")?.to_owned();
    let digest = required_digest(artifact.get("sha256"), "artifact.sha256")?.to_owned();
    validate_report(&normalized, &path, &digest)?;

    Ok(evidence.clone())
}

fn validate_report(report: &Value, path: &str, digest: &str) -> Result<(), Failure> {
    let object = input_object(report, "report")?;
    reject_unknown(
        object,
        &[
            "artifact",
            "bytecode",
            "evidence_kind",
            "functions",
            "discovery_completeness",
            "runtime_execution",
            "diagnostics",
            "limitations",
        ],
        "report",
    )?;
    let artifact = required_object(object, "artifact")?;

    validate_artifact(artifact, path, digest)?;
    let bytecode = required_object(object, "bytecode")?;
    validate_bytecode(bytecode)?;
    validate_functions(object.get("functions"), required_u64(bytecode, "bytes")?)?;
    validate_diagnostics(required_object(object, "diagnostics")?)?;
    validate_limitations(object.get("limitations"))?;

    required_text(object, "evidence_kind")?;
    required_text(object, "discovery_completeness")?;
    required_text(object, "runtime_execution")?;

    Ok(())
}

fn validate_artifact(
    artifact: &Map<String, Value>,
    expected_path: &str,
    expected_digest: &str,
) -> Result<(), Failure> {
    reject_unknown(artifact, &["path", "sha256", "bytes", "encoding"], "artifact")?;
    if required_text(artifact, "path")? != expected_path {
        return Err(invalid(
            "report artifact path does not match the selected artifact",
        ));
    }
    if required_text(artifact, "sha256")? != expected_digest {
        return Err(invalid(
            "report artifact digest does not match the selected artifact",
        ));
    }

    let bytes = required_u64(artifact, "bytes")?;
    if bytes > MAX_INPUT_BYTES {
        return Err(invalid("report artifact exceeds the EVM input bound"));
    }

    match required_text(artifact, "encoding")? {
        "raw" | "hex" => Ok(()),
        _ => Err(invalid("report artifact encoding must be raw or hex")),
    }
}

fn validate_bytecode(bytecode: &Map<String, Value>) -> Result<(), Failure> {
    reject_unknown(
        bytecode,
        &[
            "sha256",
            "bytes",
            "hex",
            "digest_algorithm",
            "kind",
            "deployment_authenticity",
            "hardfork",
            "metadata",
        ],
        "bytecode",
    )?;
    required_digest(bytecode.get("sha256"), "bytecode.sha256")?;
    let bytes = required_u64(bytecode, "bytes")?;
    if bytes > MAX_INPUT_BYTES {
        return Err(invalid("report bytecode exceeds the EVM input bound"));
    }

    let encoded = required_string(bytecode, "hex")?;
    if encoded.len() != bytes as usize * 2 || !is_lowercase_hex(encoded) {
        return Err(invalid(
            "report bytecode.hex must contain exactly two lowercase hex characters per byte",
        ));
    }
    if required_text(bytecode, "digest_algorithm")? != "sha256" {
        return Err(invalid("report bytecode digest algorithm must be sha256"));
    }

    required_text(bytecode, "kind")?;
    required_text(bytecode, "deployment_authenticity")?;
    required_text(bytecode, "hardfork")?;
    if let Some(metadata) = bytecode.get("metadata") {
        if !metadata.is_null() && !metadata.is_object() {
            return Err(invalid("report bytecode.metadata must be an object or null"));
        }
    } else {
        return Err(invalid("report bytecode.metadata is required"));
    }

    Ok(())
}

fn validate_functions(value: Option<&Value>, bytecode_bytes: u64) -> Result<(), Failure> {
    let functions = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("report.functions must be an array"))?;

    for function in functions {
        let function = function
            .as_object()
            .ok_or_else(|| invalid("each report function must be an object"))?;
        reject_unknown(
            function,
            &[
                "selector",
                "bytecode_offset",
                "dispatch",
                "inferred_arguments",
                "inferred_state_mutability",
            ],
            "function",
        )?;
        let selector = required_text(function, "selector")?;
        if selector.len() != 10 || !selector.starts_with("0x") || !is_lowercase_hex(&selector[2..])
        {
            return Err(invalid(
                "report function selectors must be 4-byte lowercase hex",
            ));
        }

        let offset = required_u64(function, "bytecode_offset")?;
        if offset > bytecode_bytes {
            return Err(invalid("report function offset is outside the bytecode"));
        }
        match required_text(function, "dispatch")? {
            "abi" | "fallback" => {}
            _ => return Err(invalid("report function dispatch must be abi or fallback")),
        }
        validate_optional_text(function, "inferred_arguments")?;
        validate_optional_text(function, "inferred_state_mutability")?;
    }

    Ok(())
}

fn validate_diagnostics(diagnostics: &Map<String, Value>) -> Result<(), Failure> {
    reject_unknown(diagnostics, &["stdout", "stderr", "truncated"], "diagnostics")?;
    required_string(diagnostics, "stdout")?;
    required_string(diagnostics, "stderr")?;
    if diagnostics
        .get("truncated")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err(invalid("report diagnostics.truncated must be a boolean"));
    }

    Ok(())
}

fn validate_limitations(value: Option<&Value>) -> Result<(), Failure> {
    let limitations = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("report.limitations must be an array"))?;
    if limitations.iter().any(|item| item.as_str().is_none()) {
        return Err(invalid("report limitations must contain only strings"));
    }

    Ok(())
}

fn reject_unknown(
    object: &Map<String, Value>,
    allowed: &[&str],
    owner: &str,
) -> Result<(), Failure> {
    if object
        .keys()
        .any(|key| !allowed.iter().any(|candidate| candidate == key))
    {
        return Err(invalid(&format!("{owner} contains an unsupported field")));
    }

    Ok(())
}

fn validate_optional_text(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = object.get(field) {
        if !value.is_null() && value.as_str().is_none() {
            return Err(invalid(&format!("report {field} must be a string or null")));
        }
    }

    Ok(())
}

fn input_object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid(&format!("{name} must be an object")))
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{field} must be an object")))
}

fn required_path(object: &Map<String, Value>) -> Result<&str, Failure> {
    let path = required_text(object, "path")?;
    if path.contains('\0') {
        return Err(invalid("path must not contain NUL bytes"));
    }

    Ok(path)
}

fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a string")))
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, Failure> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative integer")))
}

fn required_digest<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    let digest = value
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && is_lowercase_hex(value))
        .ok_or_else(|| invalid(&format!("{field} must be a lowercase SHA-256 digest")))?;

    Ok(digest)
}

fn is_lowercase_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "EVM interface report is invalid.".into(),
        false,
        "Provide a complete report bound to the selected artifact.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
