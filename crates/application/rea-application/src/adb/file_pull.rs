//! Read-only validation of a captured 'pull_adb_file' result.
//!
//! The ADB provider owns device access, host-file creation, digesting, and
//! cleanup. This boundary only checks the retained facts and keeps the
//! caller's serial, remote path, output identity, and partial digest state.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "pull_adb_file";

/// Validate the caller-selected ADB request without contacting a device.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let request = request_value(input)?;
    let object = request
        .as_object()
        .ok_or_else(|| invalid("pull_adb_file input must be an object"))?;
    reject_unknown_fields(object, &["serial", "device_path", "output_directory"])?;

    validate_serial(object.get("serial"), "serial")?;
    let device_path = non_empty_string(object.get("device_path"), "device_path")?;
    validate_device_path(device_path, "device_path")?;
    validate_local_path(object.get("output_directory"), "output_directory")?;
    Ok(())
}

/// Normalize a provider result or an Evidence wrapper into its result shape.
pub fn normalize(input: &Value) -> Result<Value, Failure> {
    let result = result_value(input)?;
    validate_result(result)?;
    Ok(result.clone())
}

/// Alias used by application adapters that expose projections uniformly.
pub fn project(input: &Value) -> Result<Value, Failure> {
    normalize(input)
}

/// Validate a captured result before Evidence wrapping.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    validate_identity(input, &result)?;
    Ok(result)
}

fn request_value(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("pull_adb_file input must be an object"))?;
    Ok(object.get("input").unwrap_or(input))
}

fn result_value(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("pull_adb_file result must be an object"))?;
    let result = object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .or_else(|| object.get("value"))
        .unwrap_or(input);
    if !result.is_object() {
        return Err(invalid("pull_adb_file result must be an object"));
    }
    Ok(result)
}

fn validate_result(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("pull_adb_file result must be an object"))?;
    reject_unknown_fields(
        object,
        &[
            "client",
            "serial",
            "device_path",
            "local_path",
            "bytes",
            "sha256",
            "digest_status",
        ],
    )?;
    validate_client(object.get("client"))?;
    validate_serial(object.get("serial"), "result.serial")?;
    let device_path = non_empty_string(object.get("device_path"), "result.device_path")?;
    validate_device_path(device_path, "result.device_path")?;
    validate_local_path(object.get("local_path"), "result.local_path")?;

    match object.get("digest_status") {
        Some(Value::String(status)) if status == "unknown" => {
            if object.contains_key("bytes") || object.contains_key("sha256") {
                return Err(invalid(
                    "unknown digest status cannot include bytes or sha256",
                ));
            }
        }
        Some(_) => return Err(invalid("digest_status must be unknown when present")),
        None => {
            nonnegative_integer(object.get("bytes"), "result.bytes")?;
            lowercase_sha256(object.get("sha256"), "result.sha256")?;
        }
    }
    Ok(())
}

fn validate_client(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("result.client must be an object"))?;
    reject_unknown_fields(
        object,
        &["binary_path", "path_source", "version", "installed_path"],
    )?;
    non_empty_string(object.get("binary_path"), "client.binary_path")?;
    match object.get("path_source").and_then(Value::as_str) {
        Some("environment" | "path") => {}
        _ => return Err(invalid("client.path_source must be environment or path")),
    }
    nullable_non_empty_string(object.get("version"), "client.version")?;
    nullable_non_empty_string(object.get("installed_path"), "client.installed_path")
}

fn validate_identity(input: &Value, result: &Value) -> Result<(), Failure> {
    let request = request_value(input)?;
    let request = request
        .as_object()
        .expect("validate_input established request object");
    let result = result
        .as_object()
        .expect("validate_result established result object");

    for field in ["serial", "device_path"] {
        if request.get(field) != result.get(field) {
            return Err(invalid(&format!(
                "result.{field} must preserve the caller-selected value"
            )));
        }
    }
    Ok(())
}

fn validate_serial(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let serial = non_empty_string(value, field)?;
    if serial.len() > 256
        || serial
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\0' | '"' | '\''))
    {
        return Err(invalid(&format!(
            "{field} must be at most 256 characters and contain no whitespace or quotes"
        )));
    }
    Ok(())
}

fn validate_device_path(path: &str, field: &str) -> Result<(), Failure> {
    if !path.starts_with('/') || path.ends_with('/') || path.bytes().any(|byte| byte == 0) {
        return Err(invalid(&format!(
            "{field} must be an absolute path naming a file without NUL"
        )));
    }

    let file_name = path.rsplit('/').next().unwrap_or_default();
    if file_name.is_empty() || matches!(file_name, "." | "..") {
        return Err(invalid(&format!(
            "{field} must name a file rather than a directory or dot segment"
        )));
    }

    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown pull_adb_file field: {field}")));
    }
    Ok(())
}

fn non_empty_string<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    let text = value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))?;
    Ok(text)
}

fn validate_local_path(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let path = non_empty_string(value, field)?;
    if path.bytes().any(|byte| byte == 0) {
        return Err(invalid(&format!("{field} must not contain NUL")));
    }
    Ok(())
}

fn nullable_non_empty_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(Value::String(text)) if !text.is_empty() => Ok(()),
        _ => Err(invalid(&format!(
            "{field} must be a non-empty string or null"
        ))),
    }
}

fn nonnegative_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| value.as_u64().is_some()) {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be a non-negative integer")))
}

fn lowercase_sha256(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let digest = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a lowercase SHA-256 digest")))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the caller-selected ADB request and its captured pull result.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
