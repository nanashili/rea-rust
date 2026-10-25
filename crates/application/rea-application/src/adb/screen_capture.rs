//! Offline normalization for a captured ADB screen image.
//!
//! The adapter owns ADB, filesystem publication, and its clock.  This module
//! consumes a completed capture or caller-owned image bytes only; it never
//! invokes ADB, creates the destination, or writes `screen.png`.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "capture_adb_screen";
const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SERIAL_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 16 * 1024;

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub binary_path: String,
    pub path_source: String,
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub client: Client,
    pub serial: String,
    pub local_path: String,
}

/// A capture is supplied by the adapter after its bounded command completes.
/// `bytes_base64` is used so this boundary remains JSON-only and deterministic.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub bytes_base64: String,
    #[serde(default)]
    pub captured_at: Option<String>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ScreenResult {
    pub client: Client,
    pub serial: String,
    pub local_path: String,
    pub bytes: usize,
    pub sha256: String,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

/// Normalize captured PNG bytes into the exact ADB screen result shape.
pub fn normalize(selection: Selection, capture: Capture) -> Result<Value, Failure> {
    validate_selection(&selection)?;
    let bytes = decode_capture(&capture)?;
    validate_capture_metadata(&capture)?;

    let (width, height) = require_png_dimensions(&bytes)?;
    let result = ScreenResult {
        client: selection.client,
        serial: selection.serial,
        local_path: selection.local_path,
        bytes: bytes.len(),
        sha256: digest(&bytes),
        width,
        height,
    };

    serde_json::to_value(result).map_err(|_| invalid("screen result is not serializable"))
}

/// Parse adapter-shaped JSON containing selection and captured bytes.
pub fn normalize_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB screen capture input must be an object"))?;
    reject_fields(
        object,
        &["selection", "capture", "result"],
        "screen capture input",
    )?;
    if let Some(result) = object.get("result") {
        return project_result(result);
    }
    let selection: Selection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("ADB screen selection is required"))?,
    )
    .map_err(|_| invalid("invalid ADB screen selection"))?;
    let capture: Capture = serde_json::from_value(
        object
            .get("capture")
            .cloned()
            .ok_or_else(|| invalid("captured screen bytes are required"))?,
    )
    .map_err(|_| invalid("invalid captured screen bytes"))?;
    normalize(selection, capture)
}

/// Validate a provider result before Evidence wrapping.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = normalize_value(input)?;
    if result != expected {
        return Err(invalid("screen result does not match the captured bytes"));
    }
    Ok(result)
}

/// Validate and return a previously retained screen result.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let result = input
        .get("result")
        .or_else(|| input.get("normalized_result"))
        .ok_or_else(|| invalid("retained screen result is required"))?;
    project_result(result)
}

fn project_result(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("screen result must be an object"))?;
    const FIELDS: &[&str] = &[
        "client",
        "serial",
        "local_path",
        "bytes",
        "sha256",
        "width",
        "height",
    ];
    reject_fields(object, FIELDS, "screen result")?;
    let result: ScreenResult = serde_json::from_value(value.clone())
        .map_err(|_| invalid("screen result has an invalid schema"))?;
    validate_client(&result.client)?;
    validate_serial(&result.serial)?;
    if result.local_path.is_empty() || result.local_path.len() > MAX_PATH_BYTES {
        return Err(invalid("screen local_path is invalid"));
    }
    if result.sha256.len() != 64 || !result.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("screen sha256 must be hexadecimal"));
    }
    if result.bytes == 0 || result.bytes > MAX_IMAGE_BYTES {
        return Err(invalid("screen byte count is outside the admitted bound"));
    }
    if result.width == Some(0) || result.height == Some(0) {
        return Err(invalid("screen dimensions must be positive when present"));
    }
    serde_json::to_value(result).map_err(|_| invalid("screen result is not serializable"))
}

fn decode_capture(capture: &Capture) -> Result<Vec<u8>, Failure> {
    if capture.bytes_base64.is_empty() {
        return Err(protocol_failure("screen capture returned no image bytes"));
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let bytes = engine
        .decode(&capture.bytes_base64)
        .map_err(|_| protocol_failure("screen capture bytes are not valid base64"))?;
    if bytes.is_empty() || bytes.len() > MAX_IMAGE_BYTES {
        return Err(resource("screen capture exceeds the 32 MiB image bound"));
    }
    if engine.encode(&bytes) != capture.bytes_base64 {
        return Err(protocol_failure(
            "screen capture bytes are not canonical base64",
        ));
    }
    Ok(bytes)
}

fn validate_capture_metadata(capture: &Capture) -> Result<(), Failure> {
    if capture.truncated {
        return Err(Failure::new_with_details(
            "truncated",
            "truncated",
            "Screen capture bytes were truncated; dimensions and digest are uncertain.".into(),
            true,
            "Repeat the bounded screen capture.".into(),
            BTreeMap::from([
                ("operation".into(), Detail::Text(OPERATION.into())),
                ("capture_truncated".into(), Detail::Flag(true)),
            ]),
        ));
    }
    if let Some(failure) = capture.failure.as_deref().filter(|value| !value.is_empty()) {
        return Err(Failure::new_with_details(
            "execution_failure",
            "execution_failure",
            failure.to_owned(),
            true,
            "Repeat the bounded screen capture after resolving the reported failure.".into(),
            BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
        ));
    }
    Ok(())
}

fn png_dimensions(bytes: &[u8]) -> (Option<u32>, Option<u32>) {
    if bytes.len() < 24 || &bytes[..8] != PNG_SIGNATURE || &bytes[12..16] != b"IHDR" {
        return (None, None);
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().expect("four-byte PNG width"));
    let height = u32::from_be_bytes(bytes[20..24].try_into().expect("four-byte PNG height"));
    if width == 0 || height == 0 {
        return (None, None);
    }
    (Some(width), Some(height))
}

/// A live `screencap -p` response must be a PNG with usable dimensions.
///
/// The TypeScript provider rejects the capture before publication when the
/// signature is absent or the header is too short. Keeping that check at the
/// capture boundary prevents a non-image payload from being retained with an
/// apparently valid digest and byte count.
fn require_png_dimensions(bytes: &[u8]) -> Result<(Option<u32>, Option<u32>), Failure> {
    let dimensions = png_dimensions(bytes);
    if dimensions.0.is_none() || dimensions.1.is_none() {
        return Err(protocol_failure(
            "screen capture did not contain a PNG payload with dimensions",
        ));
    }
    Ok(dimensions)
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    validate_client(&selection.client)?;
    validate_serial(&selection.serial)?;
    if selection.local_path.is_empty()
        || selection.local_path.len() > MAX_PATH_BYTES
        || selection.local_path.contains('\0')
    {
        return Err(invalid("screen local_path is invalid"));
    }
    Ok(())
}

fn validate_client(client: &Client) -> Result<(), Failure> {
    if client.binary_path.trim().is_empty()
        || !matches!(client.path_source.as_str(), "environment" | "path")
        || client.version.as_deref().is_some_and(str::is_empty)
        || client.installed_path.as_deref().is_some_and(str::is_empty)
    {
        return Err(invalid("ADB client identity is invalid"));
    }
    Ok(())
}

fn validate_serial(serial: &str) -> Result<(), Failure> {
    if serial.is_empty()
        || serial.len() > MAX_SERIAL_BYTES
        || serial.chars().any(|character| {
            character.is_whitespace() || character == '\0' || character == '"' || character == '\''
        })
    {
        return Err(invalid("ADB device serial is invalid"));
    }
    Ok(())
}

fn reject_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown {label} field: {field}")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the selected ADB device and a bounded captured screen result.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new_with_details(
        "artifact_operation_failed",
        "execution_failure",
        reason.to_owned(),
        false,
        "Provide a complete PNG capture and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new_with_details(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Provide a smaller bounded screen capture.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
