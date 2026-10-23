//! Offline projections for ADB feature and service inventories.
//!
//! The host adapter owns ADB execution and device selection.  These
//! operation-specific projections consume only a bounded captured response;
//! they never contact a device, merge the two inventories, or infer facts
//! from an unrecognized line.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const FEATURES_OPERATION: &str = "list_adb_features";
pub const SERVICES_OPERATION: &str = "list_adb_services";

const MAX_CAPTURE_BYTES: usize = 4 * 1024 * 1024;
const MAX_REPORTED_UNPARSED_LINES: usize = 10;
const MAX_SERIAL_BYTES: usize = 256;
const MAX_TEXT_BYTES: usize = 16 * 1024;

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
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Feature {
    pub name: String,
    pub version: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Service {
    pub name: String,
    pub interface: Option<String>,
}

/// Project a captured `pm list features` response.
pub fn inspect_features(selection: Selection, capture: Capture) -> Result<Value, Failure> {
    validate_selection(&selection, FEATURES_OPERATION)?;
    validate_capture(&capture, FEATURES_OPERATION)?;

    let (features, unparsed_lines) = parse_features(&capture.stdout);
    let (unparsed_lines, coverage) =
        report_capture_state(unparsed_lines, capture.truncated, capture.stderr.trim());

    serde_json::to_value(json!({
        "client": selection.client,
        "serial": selection.serial,
        "features": features,
        "unparsed_lines": unparsed_lines,
        "coverage": coverage,
    }))
    .map_err(|_| invalid(FEATURES_OPERATION, "feature result is not serializable"))
}

/// Project a captured `service list` response.
pub fn inspect_services(selection: Selection, capture: Capture) -> Result<Value, Failure> {
    validate_selection(&selection, SERVICES_OPERATION)?;
    validate_capture(&capture, SERVICES_OPERATION)?;

    let (services, unparsed_lines) = parse_services(&capture.stdout);
    let (unparsed_lines, coverage) =
        report_capture_state(unparsed_lines, capture.truncated, capture.stderr.trim());

    serde_json::to_value(json!({
        "client": selection.client,
        "serial": selection.serial,
        "services": services,
        "unparsed_lines": unparsed_lines,
        "coverage": coverage,
    }))
    .map_err(|_| invalid(SERVICES_OPERATION, "service result is not serializable"))
}

/// Parse the adapter-shaped feature request while retaining selection facts.
pub fn inspect_features_value(input: &Value) -> Result<Value, Failure> {
    let (selection, capture) = parse_input(input, FEATURES_OPERATION)?;
    inspect_features(selection, capture)
}

/// Parse the adapter-shaped service request while retaining selection facts.
pub fn inspect_services_value(input: &Value) -> Result<Value, Failure> {
    let (selection, capture) = parse_input(input, SERVICES_OPERATION)?;
    inspect_services(selection, capture)
}

/// Validate that a captured feature result matches its source capture.
pub fn retain_features_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = inspect_features_value(input)?;
    validate_result(&result, FEATURES_OPERATION, "features")?;
    if result != expected {
        return Err(invalid(
            FEATURES_OPERATION,
            "feature result does not match the captured response",
        ));
    }
    Ok(result)
}

/// Validate that a captured service result matches its source capture.
pub fn retain_services_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = inspect_services_value(input)?;
    validate_result(&result, SERVICES_OPERATION, "services")?;
    if result != expected {
        return Err(invalid(
            SERVICES_OPERATION,
            "service result does not match the captured response",
        ));
    }
    Ok(result)
}

fn parse_input(input: &Value, operation: &str) -> Result<(Selection, Capture), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "ADB capture input must be an object"))?;
    reject_fields(object, &["selection", "capture", "probe"], operation)?;
    let selection = object
        .get("selection")
        .cloned()
        .ok_or_else(|| invalid(operation, "ADB selection is required"))?;
    let capture = object
        .get("capture")
        .or_else(|| object.get("probe"))
        .cloned()
        .ok_or_else(|| invalid(operation, "bounded ADB capture is required"))?;
    let selection: Selection = serde_json::from_value(selection)
        .map_err(|_| invalid(operation, "invalid ADB selection"))?;
    let capture: Capture = serde_json::from_value(capture)
        .map_err(|_| invalid(operation, "invalid bounded ADB capture"))?;
    Ok((selection, capture))
}

fn validate_selection(selection: &Selection, operation: &str) -> Result<(), Failure> {
    if selection.serial.is_empty()
        || selection.serial.len() > MAX_SERIAL_BYTES
        || selection.serial.chars().any(|character| {
            character.is_whitespace() || character == '\0' || character == '"' || character == '\''
        })
    {
        return Err(invalid(operation, "ADB device serial is invalid"));
    }
    if !valid_client(&selection.client) {
        return Err(invalid(operation, "ADB client identity is invalid"));
    }
    Ok(())
}

fn validate_capture(capture: &Capture, operation: &str) -> Result<(), Failure> {
    if capture.stdout.len() > MAX_CAPTURE_BYTES || capture.stderr.len() > MAX_CAPTURE_BYTES {
        return Err(Failure::new(
            "resource_constraint",
            "resource_constraint",
            "ADB capability capture exceeds the 4 MiB bound.".into(),
            false,
            "Provide a bounded ADB capture and retry.".into(),
            BTreeMap::from([
                ("operation".into(), Detail::Text(operation.into())),
                (
                    "max_capture_bytes".into(),
                    Detail::Count(MAX_CAPTURE_BYTES as u64),
                ),
            ]),
        ));
    }
    Ok(())
}

fn parse_features(stdout: &str) -> (Vec<Feature>, Vec<String>) {
    let mut features = Vec::new();
    let mut unparsed = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(rest) = line.strip_prefix("feature:") else {
            unparsed.push(line.to_owned());
            continue;
        };
        let mut parts = rest.splitn(2, '=');
        let Some(name) = parts
            .next()
            .filter(|name| !name.is_empty() && !name.chars().any(char::is_whitespace))
        else {
            unparsed.push(line.to_owned());
            continue;
        };
        let version = match parts.next() {
            None => None,
            Some(value) => parse_feature_version(value),
        };
        if parts.next().is_some() || (rest.contains('=') && version.is_none()) {
            unparsed.push(line.to_owned());
            continue;
        }
        features.push(Feature {
            name: name.to_owned(),
            version,
        });
    }
    (features, unparsed)
}

fn parse_feature_version(value: &str) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    if let Some(hex) = value.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    value.parse::<u64>().ok()
}

fn parse_services(stdout: &str) -> (Vec<Service>, Vec<String>) {
    let mut services = Vec::new();
    let mut unparsed = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.is_empty() || starts_found_services(trimmed) {
            continue;
        }
        let Some((prefix, interface)) = line.split_once("[") else {
            unparsed.push(trimmed.to_owned());
            continue;
        };
        let Some(interface) = interface.strip_suffix(']') else {
            unparsed.push(trimmed.to_owned());
            continue;
        };
        let name = prefix
            .trim()
            .split_once(' ')
            .map_or(prefix.trim(), |(_, name)| name.trim())
            .strip_suffix(':')
            .unwrap_or_default();
        if name.is_empty() || !valid_service_name(name) {
            unparsed.push(trimmed.to_owned());
            continue;
        }
        services.push(Service {
            name: name.to_owned(),
            interface: (!interface.is_empty()).then(|| interface.to_owned()),
        });
    }
    (services, unparsed)
}

fn starts_found_services(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Found ") else {
        return false;
    };
    rest.strip_suffix(" services:").is_some_and(|count| {
        !count.is_empty() && count.chars().all(|character| character.is_ascii_digit())
    })
}

fn valid_service_name(name: &str) -> bool {
    name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'$' | b'/' | b'-')
    })
}

fn report_capture_state(
    mut unparsed: Vec<String>,
    truncated: bool,
    stderr: &str,
) -> (Vec<String>, &'static str) {
    if truncated {
        unparsed.push("capture truncated; omitted lines are unknown".into());
    }
    if !stderr.is_empty() {
        unparsed.push("capture reported stderr; parsed stdout may be incomplete".into());
    }
    let coverage = if unparsed.is_empty() {
        "complete"
    } else {
        "partial"
    };
    unparsed.truncate(MAX_REPORTED_UNPARSED_LINES);
    (unparsed, coverage)
}

fn validate_result(value: &Value, operation: &str, rows_field: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(operation, "ADB inventory result must be an object"))?;
    let fields = if rows_field == "features" {
        &["client", "serial", "features", "unparsed_lines", "coverage"][..]
    } else {
        &["client", "serial", "services", "unparsed_lines", "coverage"][..]
    };
    reject_fields(object, fields, operation)?;
    let selection = object
        .get("client")
        .ok_or_else(|| invalid(operation, "result client is required"))?;
    let client = serde_json::from_value::<Client>(selection.clone())
        .map_err(|_| invalid(operation, "result client is invalid"))?;
    if !valid_client(&client) {
        return Err(invalid(operation, "result client is invalid"));
    }
    if object
        .get("serial")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || object
            .get("unparsed_lines")
            .and_then(Value::as_array)
            .is_none()
        || !matches!(
            object.get("coverage").and_then(Value::as_str),
            Some("complete" | "partial")
        )
    {
        return Err(invalid(
            operation,
            "ADB inventory result has invalid provenance or coverage",
        ));
    }
    let rows = object
        .get(rows_field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(operation, &format!("result {rows_field} must be an array")))?;
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| invalid(operation, "inventory row must be an object"))?;
        if rows_field == "features" {
            reject_fields(row, &["name", "version"], operation)?;
            if row
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || row
                    .get("version")
                    .is_none_or(|version| !version.is_null() && version.as_u64().is_none())
            {
                return Err(invalid(operation, "feature row is invalid"));
            }
        } else {
            reject_fields(row, &["name", "interface"], operation)?;
            if row
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || row
                    .get("interface")
                    .is_none_or(|interface| !interface.is_null() && interface.as_str().is_none())
            {
                return Err(invalid(operation, "service row is invalid"));
            }
        }
    }
    let unparsed = object
        .get("unparsed_lines")
        .and_then(Value::as_array)
        .expect("validated unparsed_lines");
    if unparsed.len() > MAX_REPORTED_UNPARSED_LINES
        || unparsed.iter().any(|line| {
            line.as_str().is_none_or(str::is_empty)
                || line
                    .as_str()
                    .is_some_and(|line| line.len() > MAX_TEXT_BYTES)
        })
    {
        return Err(invalid(
            operation,
            "unparsed_lines is invalid or exceeds its bound",
        ));
    }
    if object.get("coverage").and_then(Value::as_str) == Some("complete") && !unparsed.is_empty() {
        return Err(invalid(
            operation,
            "complete coverage cannot contain unparsed lines",
        ));
    }
    Ok(())
}

fn valid_client(client: &Client) -> bool {
    !client.binary_path.trim().is_empty()
        && matches!(client.path_source.as_str(), "environment" | "path")
        && client
            .version
            .as_deref()
            .is_none_or(|version| !version.is_empty())
        && client
            .installed_path
            .as_deref()
            .is_none_or(|path| !path.is_empty())
}

fn reject_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    operation: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(operation, &format!("unknown input field: {field}")));
    }
    Ok(())
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the selected ADB client, serial, and bounded command capture.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}
