//! Offline projection of one captured `adb shell settings get` response.
//!
//! This module does not contact ADB. The caller owns command execution and
//! supplies the selected serial, exact setting identity, and captured output.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "read_adb_setting";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const REDACTED_VALUE: &str = "[REDACTED]";

/// Project a captured settings command. Both the flat adapter shape and the
/// `{ request, capture }` shape are accepted so the projection can be used by
/// either the host adapter or a retained workflow record.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB setting input must be an object"))?;
    let (request, capture) = match (object.get("request"), object.get("capture")) {
        (Some(request), Some(capture)) => (
            request
                .as_object()
                .ok_or_else(|| invalid("request must be an object"))?,
            capture
                .as_object()
                .ok_or_else(|| invalid("capture must be an object"))?,
        ),
        _ => (object, object),
    };

    let client = request.get("client").cloned().unwrap_or(Value::Null);
    let serial = required_text(request, "serial")?;
    let namespace = required_text(request, "namespace")?;
    let key = required_text(request, "key")?;
    validate_serial(serial)?;
    validate_namespace(namespace)?;
    validate_key(key)?;

    let stdout = capture
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured settings stdout is required"))?;
    let stderr = capture.get("stderr").and_then(Value::as_str).unwrap_or("");
    if stdout.len() > MAX_OUTPUT_BYTES || stderr.len() > MAX_OUTPUT_BYTES {
        return Err(resource_failure());
    }
    if let Some(code) = capture.get("exit_code").and_then(Value::as_i64) {
        if code != 0 {
            return Err(command_failure(code, stderr));
        }
    }

    let (mut value, device_reported_null) = parse_settings_output(stdout);
    let explicitly_sensitive = capture
        .get("sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if explicitly_sensitive && value.is_some() {
        value = Some(REDACTED_VALUE.to_owned());
    }

    Ok(json!({
        "client": client,
        "serial": serial,
        "namespace": namespace,
        "key": key,
        "value": value,
        "device_reported_null": device_reported_null,
        "value_redacted": explicitly_sensitive && !device_reported_null,
        "evidence": {
            "operation": OPERATION,
            "source": "adb:shell settings get",
            "serial": serial,
            "namespace": namespace,
            "key": key,
            "command_succeeded": true,
        },
    }))
}

pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    inspect(input)
}

/// Matches the provider parser: remove exactly one terminal CRLF/LF, then
/// preserve every other character in the returned setting value.
fn parse_settings_output(stdout: &str) -> (Option<String>, bool) {
    let trimmed = if stdout.ends_with("\r\n") {
        &stdout[..stdout.len() - 2]
    } else if stdout.ends_with('\n') {
        &stdout[..stdout.len() - 1]
    } else {
        stdout
    };
    if trimmed == "null" {
        (None, true)
    } else {
        (Some(trimmed.to_owned()), false)
    }
}

fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn validate_serial(serial: &str) -> Result<(), Failure> {
    if utf16_length(serial) > 256
        || serial.chars().any(|character| {
            character.is_whitespace() || character == '\0' || character == '"' || character == '\''
        })
    {
        return Err(invalid("serial contains whitespace, quotes, or NUL"));
    }
    Ok(())
}

fn validate_namespace(namespace: &str) -> Result<(), Failure> {
    if matches!(namespace, "system" | "secure" | "global") {
        Ok(())
    } else {
        Err(invalid("namespace must be system, secure, or global"))
    }
}

fn validate_key(key: &str) -> Result<(), Failure> {
    if utf16_length(key) > 256
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(invalid(
            "key must contain only letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}

/// Zod's string length checks count UTF-16 code units, so use the same unit
/// for the Rust boundary instead of rejecting valid non-ASCII serial lengths
/// based on their UTF-8 byte expansion.
fn utf16_length(value: &str) -> usize {
    value.encode_utf16().count()
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the selected ADB setting and bounded captured output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource_failure() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "Captured settings output exceeds the retained output bound.".into(),
        false,
        "Provide a smaller bounded settings capture.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            (
                "maximum_output_bytes",
                Detail::Count(MAX_OUTPUT_BYTES as u64),
            ),
        ]),
    )
}

fn command_failure(exit_code: i64, stderr: &str) -> Failure {
    Failure::new(
        "provider_failure",
        "provider_failure",
        format!("ADB settings command failed with exit code {exit_code}: {stderr}"),
        false,
        "Inspect the captured ADB error and retry with the selected device.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("exit_code", Detail::Count(exit_code.unsigned_abs())),
        ]),
    )
}
