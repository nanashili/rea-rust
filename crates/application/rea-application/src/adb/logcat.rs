//! Offline projection of a bounded, captured `adb logcat` response.
//!
//! Device access belongs to the provider adapter. This module retains the
//! selected request, producer text, byte accounting, and capture uncertainty.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "read_adb_logcat";
const MAX_COUNT: u64 = 10_000;
const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub client: Client,
    pub serial: String,
    pub count: u64,
    pub buffer: Buffer,
    pub pid: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub binary_path: String,
    pub path_source: String,
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Buffer {
    Main,
    System,
    Radio,
    Events,
    Crash,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub stdout: String,
    #[serde(default)]
    pub stdout_bytes: Option<u64>,
    #[serde(default)]
    pub output_truncated: bool,
    #[serde(default)]
    pub stdout_invalid_utf8: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ResultProjection {
    pub client: Client,
    pub serial: String,
    pub count: u64,
    pub buffer: Buffer,
    pub pid: Option<u64>,
    pub lines: Vec<String>,
    pub total_bytes: u64,
    pub coverage: Coverage,
    pub producer_text: String,
    pub parse_failures: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
}

/// Parse adapter-shaped `{ request, capture }` input without contacting ADB.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Input must be an object"))?;
    let request: Request = serde_json::from_value(required(object, "request")?.clone())
        .map_err(|_| invalid("Invalid logcat request"))?;
    validate_request(&request)?;
    let capture: Capture = serde_json::from_value(required(object, "capture")?.clone())
        .map_err(|_| invalid("Invalid captured logcat output"))?;
    project(request, capture).and_then(|result| {
        serde_json::to_value(result).map_err(|_| invalid("Result is not serializable"))
    })
}

fn project(request: Request, capture: Capture) -> Result<ResultProjection, Failure> {
    let total_bytes = capture
        .stdout_bytes
        .unwrap_or_else(|| capture.stdout.as_bytes().len() as u64);
    if total_bytes > MAX_OUTPUT_BYTES {
        return Err(resource_failure());
    }

    let mut lines: Vec<String> = capture
        .stdout
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line).to_owned())
        .collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    let count_reached = lines.len() >= request.count as usize;
    let trimmed = lines.len() > request.count as usize;
    if trimmed {
        lines = lines.split_off(lines.len() - request.count as usize);
    }

    let mut limitations = Vec::new();
    if trimmed || count_reached || capture.output_truncated {
        limitations.push("The captured dump is partial; the newest lines are retained when the count cap trims it.".into());
    }
    if capture.stdout_invalid_utf8 {
        limitations.push("Captured stdout contained invalid UTF-8; replacement text does not preserve the original bytes.".into());
    }

    Ok(ResultProjection {
        client: request.client,
        serial: request.serial,
        count: request.count,
        buffer: request.buffer,
        pid: request.pid,
        lines,
        total_bytes,
        coverage: if limitations.is_empty() {
            Coverage::Complete
        } else {
            Coverage::Partial
        },
        producer_text: capture.stdout,
        parse_failures: limitations,
    })
}

fn validate_request(request: &Request) -> Result<(), Failure> {
    if request.serial.is_empty() || request.client.binary_path.is_empty() {
        return Err(invalid("ADB identity fields must be non-empty"));
    }
    if request.count == 0 || request.count > MAX_COUNT {
        return Err(invalid("count must be between 1 and 10000"));
    }
    if request.pid.is_some_and(|pid| pid == 0) {
        return Err(invalid("pid must be positive"));
    }
    Ok(())
}

fn required<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a Value, Failure> {
    object
        .get(key)
        .ok_or_else(|| invalid(&format!("{key} is required")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide the selected ADB request and bounded captured output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource_failure() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "Captured logcat output exceeds the retained output bound.".into(),
        false,
        "Provide a smaller bounded logcat capture.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("maximum_output_bytes", Detail::Count(MAX_OUTPUT_BYTES)),
        ]),
    )
}
