//! Projection of caller-supplied native UI observation Evidence.
//!
//! The macOS helper owns process and accessibility capture.  This module only
//! validates an already captured result and returns its complete Evidence;
//! it has no process, window, screenshot, filesystem, or UI authority.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "observe_native_ui";

const MAX_NODES: usize = 100_000;
const MAX_STEPS: usize = 10_000;
const MAX_PATH_LENGTH: usize = 256;
const MAX_TEXT_BYTES: usize = 1 << 20;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Screenshot {
    mime_type: String,
    base64: String,
    sha256: String,
    width: u64,
    height: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Window {
    pid: u64,
    window_id: u64,
    executable: String,
    launch_time: f64,
    title: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Node {
    path: Vec<u64>,
    role: Option<String>,
    title: Option<String>,
    value: Option<String>,
    actions: Vec<String>,
    children_count: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    window: Window,
    nodes: Vec<Node>,
    truncated: bool,
    screenshot: Option<Screenshot>,
    gaps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Step {
    index: u64,
    kind: String,
    before: Snapshot,
    after: Option<Snapshot>,
    outcome: String,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Observation {
    target_sha256: String,
    initial: Snapshot,
    steps: Vec<Step>,
    restore: String,
    limitations: Vec<String>,
}

/// Validate and project a captured observation or an Evidence envelope.
pub fn observe(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("native UI observation requires retained Evidence"))?;
    let (record, result) = authenticated_result(evidence)?;
    let observation: Observation = serde_json::from_value(result)
        .map_err(|error| invalid(&format!("invalid native UI observation: {error}")))?;

    validate_observation(&observation)?;

    if !record.operation_matches(OPERATION) {
        return Err(integrity("native UI Evidence operation is not observe_native_ui"));
    }

    // Preserve the complete authenticated envelope, including provider,
    // subject, limitations, and source-specific fields unknown to this
    // operation. Downstream consumers can use normalized_result when they
    // need the validated observation itself.
    Ok(evidence.clone())
}

/// Parse either the public result directly or its Evidence `result` projection.
pub fn normalize_value(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("native UI observation requires retained Evidence"))?;
    let (_, result) = authenticated_result(evidence)?;
    let observation: Observation = serde_json::from_value(result.clone())
        .map_err(|error| invalid(&format!("invalid native UI observation: {error}")))?;

    validate_observation(&observation)?;
    Ok(result)
}

/// Confirm that a runtime result is exactly the supplied captured observation.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = normalize_value(input)?;
    if result != expected {
        return Err(invalid(
            "native UI result does not match captured observation",
        ));
    }
    Ok(result)
}

/// Validate captured input without contacting a provider.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    observe(input).map(|_| ())
}

fn authenticated_result(input: &Value) -> Result<(EvidenceRecord, Value), Failure> {
    let raw = serde_json::value::to_raw_value(input)
        .map_err(|error| integrity(&format!("native UI Evidence is not valid JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("native UI Evidence is not authenticated: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("native UI Evidence operation is not observe_native_ui"));
    }
    let result = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("native UI Evidence result is invalid JSON: {error}")))?;
    Ok((record, result))
}

fn validate_observation(observation: &Observation) -> Result<(), Failure> {
    validate_text(&observation.target_sha256, "target_sha256")?;
    if observation.restore != "leave-as-is" {
        return Err(invalid("native UI restore must be leave-as-is"));
    }
    validate_snapshot(&observation.initial)?;
    if observation.steps.len() > MAX_STEPS {
        return Err(resource("native UI observation contains too many steps"));
    }

    for step in &observation.steps {
        if step.index > MAX_SAFE_INTEGER {
            return Err(resource(
                "native UI step index exceeds the safe integer bound",
            ));
        }
        if !matches!(step.outcome.as_str(), "completed" | "failed" | "cancelled") {
            return Err(invalid("native UI step outcome is invalid"));
        }
        validate_text(&step.kind, "step.kind")?;
        if let Some(reason) = &step.reason {
            validate_text(reason, "step.reason")?;
        }
        validate_snapshot(&step.before)?;
        if let Some(after) = &step.after {
            validate_snapshot(after)?;
        }
    }

    for limitation in &observation.limitations {
        validate_text(limitation, "limitation")?;
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Snapshot) -> Result<(), Failure> {
    if snapshot.window.pid == 0
        || snapshot.window.window_id == 0
        || snapshot.window.pid > MAX_SAFE_INTEGER
        || snapshot.window.window_id > MAX_SAFE_INTEGER
    {
        return Err(invalid("native UI window identity must be positive"));
    }
    validate_text(&snapshot.window.executable, "window.executable")?;
    validate_text(&snapshot.window.title, "window.title")?;
    if !snapshot.launch_time.is_finite() {
        return Err(invalid("window.launch_time must be finite"));
    }
    if snapshot.nodes.len() > MAX_NODES {
        return Err(resource(
            "native UI snapshot contains too many accessibility nodes",
        ));
    }
    for node in &snapshot.nodes {
        if node.path.len() > MAX_PATH_LENGTH {
            return Err(resource("native UI accessibility path is too long"));
        }
        for value in [&node.role, &node.title, &node.value] {
            if let Some(value) = value {
                validate_text(value, "accessibility node text")?;
            }
        }
        for action in &node.actions {
            validate_text(action, "accessibility action")?;
        }
        if node.path.iter().any(|value| *value > MAX_SAFE_INTEGER)
            || node
                .children_count
                .is_some_and(|value| value > MAX_SAFE_INTEGER)
        {
            return Err(resource(
                "native UI accessibility numbers exceed the safe integer bound",
            ));
        }
    }
    for gap in &snapshot.gaps {
        validate_text(gap, "snapshot gap")?;
    }
    if let Some(screenshot) = &snapshot.screenshot {
        validate_screenshot(screenshot)?;
    }
    Ok(())
}

fn validate_screenshot(screenshot: &Screenshot) -> Result<(), Failure> {
    if screenshot.mime_type != "image/png"
        || screenshot.width == 0
        || screenshot.height == 0
        || screenshot.width > i32::MAX as u64
        || screenshot.height > i32::MAX as u64
    {
        return Err(invalid("native UI screenshot metadata is invalid"));
    }
    if screenshot.base64.len() > MAX_TEXT_BYTES {
        return Err(resource(
            "native UI screenshot base64 exceeds its byte limit",
        ));
    }
    require_sha256(&screenshot.sha256, "screenshot.sha256")?;
    let bytes = STANDARD
        .decode(&screenshot.base64)
        .map_err(|_| invalid("native UI screenshot base64 is invalid"))?;
    if STANDARD.encode(&bytes) != screenshot.base64 {
        return Err(invalid("native UI screenshot base64 is not canonical"));
    }
    if Sha256::digest(&bytes).as_slice() != hex_bytes(&screenshot.sha256).as_slice() {
        return Err(invalid("native UI screenshot digest mismatch"));
    }
    let (width, height) = png_dimensions(&bytes)
        .ok_or_else(|| invalid("native UI screenshot is not a PNG with an IHDR chunk"))?;
    if width != screenshot.width || height != screenshot.height {
        return Err(invalid("native UI screenshot dimensions mismatch"));
    }
    Ok(())
}

fn png_dimensions(bytes: &[u8]) -> Option<(u64, u64)> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if bytes.len() < 24
        || &bytes[..8] != SIGNATURE
        || u32::from_be_bytes(bytes[8..12].try_into().ok()?) != 13
        || &bytes[12..16] != b"IHDR"
    {
        return None;
    }
    let width = u32::from_be_bytes(bytes[16..20].try_into().ok()?) as u64;
    let height = u32::from_be_bytes(bytes[20..24].try_into().ok()?) as u64;
    if width == 0 || height == 0 || width > i32::MAX as u64 || height > i32::MAX as u64 {
        return None;
    }
    Some((width, height))
}

fn require_sha256(value: &str, field: &str) -> Result<(), Failure> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(())
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex(pair[0]) << 4) | hex(pair[1]))
        .collect()
}

fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn validate_text(value: &str, field: &str) -> Result<(), Failure> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(resource(&format!("{field} exceeds its byte limit")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a bounded native UI observation captured from the selected target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Request a smaller native UI observation within the supported bounds.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.to_owned(),
        false,
        "Provide an authenticated, intact observe_native_ui Evidence record.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
