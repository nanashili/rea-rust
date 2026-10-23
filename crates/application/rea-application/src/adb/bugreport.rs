//! Offline normalization of captured `adb bugreport` metadata.
//!
//! A provider adapter owns device access and filesystem publication. This
//! module only validates and normalizes the request and captured outcome.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "collect_adb_bugreport";

/// Normalize adapter-shaped `{ request, capture }` metadata without contacting ADB.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB bugreport input must be an object"))?;
    if let Some(result) = object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .or_else(|| object.get("value"))
    {
        return project_result(result);
    }
    let request = object
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("request is required"))?;
    let capture = object
        .get("capture")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("capture metadata is required"))?;
    validate_request(request)?;
    normalize(request, capture)
}

fn project_result(result: &Value) -> Result<Value, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("ADB bugreport result must be an object"))?;
    let serial = required_string(object, "serial")?;
    validate_serial(serial)?;
    let output_directory = required_string(object, "output_directory")?;
    validate_local_path(output_directory, "output_directory")?;
    optional_path(object, "local_path")?;
    optional_path(object, "adb_reported_path")?;
    optional_nonnegative(object, "bytes")?;
    optional_digest(object, "sha256")?;
    optional_integer(object, "exit_code")?;
    optional_nonnegative(object, "elapsed_ms")?;
    for field in ["truncated", "nonzero_exit", "partial"] {
        if let Some(value) = object.get(field) {
            if !value.is_boolean() {
                return Err(invalid(&format!("{field} must be a boolean when provided")));
            }
        }
    }
    if let Some(limitations) = object.get("limitations") {
        if !limitations
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
        {
            return Err(invalid("limitations must contain strings when provided"));
        }
    }
    Ok(result.clone())
}

fn validate_request(request: &Map<String, Value>) -> Result<(), Failure> {
    let serial = required_string(request, "serial")?;
    validate_serial(serial)?;
    let output_directory = required_string(request, "output_directory")?;
    validate_local_path(output_directory, "output_directory")?;
    Ok(())
}

fn validate_serial(serial: &str) -> Result<(), Failure> {
    if serial.chars().count() > 256 {
        return Err(invalid("serial must be at most 256 characters"));
    }
    if serial
        .chars()
        .any(|character| character.is_whitespace() || matches!(character, '\0' | '"' | '\''))
    {
        return Err(invalid("serial contains whitespace or quotes"));
    }
    Ok(())
}

fn validate_local_path(path: &str, field: &str) -> Result<(), Failure> {
    if path.is_empty() {
        return Err(invalid(&format!("{field} must be non-empty")));
    }
    if path.contains('\0') {
        return Err(invalid(&format!("{field} cannot contain NUL bytes")));
    }
    Ok(())
}

fn normalize(request: &Map<String, Value>, capture: &Map<String, Value>) -> Result<Value, Failure> {
    let serial = required_string(request, "serial")?;
    let output_directory = required_string(request, "output_directory")?;
    let local_path = optional_path(capture, "local_path")?;
    let reported_path = optional_path(capture, "adb_reported_path")?;
    let bytes = optional_nonnegative(capture, "bytes")?;
    let sha256 = optional_digest(capture, "sha256")?;
    let exit_code = optional_integer(capture, "exit_code")?;
    let elapsed_ms = optional_nonnegative(capture, "elapsed_ms")?;
    let truncated = is_truncated(capture);
    let nonzero_exit = exit_code.is_some_and(|code| code != 0);
    let partial =
        truncated || nonzero_exit || capture.get("partial").and_then(Value::as_bool) == Some(true);
    let mut limitations = Vec::new();
    if truncated {
        limitations.push("Captured adb output was truncated.".to_owned());
    }
    if nonzero_exit {
        limitations.push("adb bugreport exited with a nonzero status.".to_owned());
    }
    if partial && local_path.is_none() {
        limitations.push("The bugreport archive was not confirmed as published.".to_owned());
    }
    if let Some(reason) = capture.get("partial_reason").and_then(Value::as_str) {
        limitations.push(reason.to_owned());
    }
    if let Some(reason) = capture.get("cleanup_reason").and_then(Value::as_str) {
        limitations.push(reason.to_owned());
    }
    limitations.sort();
    limitations.dedup();

    let mut result = json!({
        "client": request.get("client").cloned().unwrap_or(Value::Null),
        "serial": serial,
        "output_directory": output_directory,
        "local_path": local_path,
        "adb_reported_path": reported_path,
        "bytes": bytes,
        "sha256": sha256,
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "started_at": capture.get("started_at").cloned().unwrap_or(Value::Null),
        "completed_at": capture.get("completed_at").cloned().unwrap_or(Value::Null),
        "truncated": truncated,
        "nonzero_exit": nonzero_exit,
        "partial": partial,
        "cleanup": capture.get("cleanup").cloned().unwrap_or(Value::Null),
        "collection": capture.get("collection").cloned().unwrap_or(Value::Null),
        "limitations": limitations,
    });
    preserve_redaction_metadata(&mut result, capture);
    Ok(result)
}

fn preserve_redaction_metadata(result: &mut Value, capture: &Map<String, Value>) {
    let Some(result_object) = result.as_object_mut() else {
        return;
    };
    for field in [
        "transport_credentials_redacted",
        "redacted_transport_credentials",
    ] {
        if let Some(value) = capture.get(field) {
            result_object.insert(field.to_owned(), value.clone());
        }
    }
    if capture.get("transport_credentials_redacted").is_some()
        || capture.get("redacted_transport_credentials").is_some()
    {
        result_object.insert(
            "transport_credentials".into(),
            Value::String("redacted".into()),
        );
    }
}

fn is_truncated(capture: &Map<String, Value>) -> bool {
    [
        "output_truncated",
        "stdout_truncated",
        "stderr_truncated",
        "truncated",
    ]
    .iter()
    .any(|field| capture.get(*field).and_then(Value::as_bool) == Some(true))
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn optional_path(object: &Map<String, Value>, field: &str) -> Result<Option<String>, Failure> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let path = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string when provided")))?;
    validate_local_path(path, field)?;
    Ok(Some(path.to_owned()))
}

fn optional_nonnegative(object: &Map<String, Value>, field: &str) -> Result<Option<u64>, Failure> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| invalid(&format!("{field} must be a nonnegative integer")))
}

fn optional_integer(object: &Map<String, Value>, field: &str) -> Result<Option<i64>, Failure> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    value
        .as_i64()
        .map(Some)
        .ok_or_else(|| invalid(&format!("{field} must be an integer")))
}

fn optional_digest(object: &Map<String, Value>, field: &str) -> Result<Option<String>, Failure> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let digest = value
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| invalid(&format!("{field} must be lowercase SHA-256 hex")))?;
    Ok(Some(digest.to_owned()))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide the selected ADB request and captured bugreport metadata.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
