//! Isolated runtime handler for retained firmware region observations.
//!
//! Binwalk execution, stable input capture, and Evidence creation remain
//! provider-owned. This module only validates the retained observation
//! envelope and delegates region normalization to the application producer.
//! It is intentionally not registered with the shared runtime dispatcher.

use rea_application::firmware;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, path::Path};

/// The public operation name shared by the TypeScript and native contracts.
pub const OPERATION: &str = firmware::regions::OPERATION;

/// Dispatch the retained inspection envelope for the public operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    inspect(&input)
}

/// Validate and project one retained firmware inspection observation.
///
/// The report and engine are caller-supplied observations. This function does
/// not read the selected path, launch Binwalk, execute extracted content, or
/// mutate the input artifact.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input)?;
    reject_unknown_fields(object)?;

    let path = required_non_empty_string(object, "path")?;
    if !Path::new(path).is_absolute() {
        return Err(invalid(
            "path must be an absolute local path",
            String::new(),
        ));
    }
    let input_size = required_input_size(object)?;
    let input_sha256 = required_digest(object, "input_sha256")?;
    let report = required_field(object, "report")?;
    let engine = required_field(object, "engine")?;

    let normalized = firmware::regions::normalize_report(path, input_size, report, engine)?;
    let normalized: Value = serde_json::from_str(normalized.get())
        .map_err(|error| invalid("normalized result is not valid JSON", error.to_string()))?;

    let mut result = normalized
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("normalized result must be an object", String::new()))?;
    result.insert("input_path".into(), Value::String(path.into()));
    result.insert("input_sha256".into(), Value::String(input_sha256.into()));
    result.insert(
        "limitations".into(),
        Value::Array(
            [
                "Reported lengths are provider values; validated content boundaries remain unknown.",
                "Signature candidates do not establish partition validity, encryption, or runtime behavior.",
                "Runtime addresses and decoded firmware content are not reported.",
            ]
            .into_iter()
            .map(Value::from)
            .collect(),
        ),
    );

    Ok(Value::Object(result))
}

fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object", String::new()))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const FIELDS: [&str; 5] = ["path", "input_size", "input_sha256", "report", "engine"];

    if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid("input contains an unknown field", String::new()));
    }

    Ok(())
}

fn required_field<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .ok_or_else(|| invalid(&format!("{field} is required"), String::new()))
}

fn required_non_empty_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            invalid(
                &format!("{field} must be a non-empty string"),
                String::new(),
            )
        })
}

fn required_input_size(object: &Map<String, Value>) -> Result<usize, Failure> {
    let size = object
        .get("input_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("input_size must be an integer", String::new()))?;

    if size == 0 || size > firmware::regions::MAX_INPUT_BYTES as u64 {
        return Err(invalid(
            "input_size is outside the firmware limit",
            String::new(),
        ));
    }

    Ok(size as usize)
}

fn required_digest<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    let digest = required_non_empty_string(object, field)?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            &format!("{field} must be a SHA-256 digest"),
            String::new(),
        ));
    }

    Ok(digest)
}

fn unknown_operation(operation: &str) -> Failure {
    invalid("unknown operation", format!("operation={operation}"))
}

fn invalid(reason: &str, detail: String) -> Failure {
    let mut details = BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]);
    if !detail.is_empty() {
        details.insert("detail", Detail::Text(detail));
    }

    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded retained firmware inspection observation and retry.".into(),
        details,
    )
}
