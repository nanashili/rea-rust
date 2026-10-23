//! Offline projection for captured `discover_webmcp_tools` observations.
//!
//! Live CDP discovery owns browser access and protocol decoding. This
//! operation-specific boundary accepts either a caller-captured normalized
//! result or authenticated Evidence, validates the retained WebMCP shape, and
//! never contacts a browser or invokes a declared tool.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "discover_webmcp_tools";

const BROWSER_SECTIONS: &[&str] = &[
    "frames",
    "dom",
    "accessibility",
    "scripts",
    "script_sources",
    "resources",
    "network_requests",
    "network_initiators",
    "console_events",
    "console_text",
    "websocket_connections",
    "websocket_frames",
    "websocket_shapes",
    "json_body_shapes",
    "workers",
    "storage",
    "storage_keys",
    "metadata",
    "webmcp_tools",
    "screenshot",
    "source_maps",
    "timeline",
];

const EXCLUSION_REASONS: &[&str] = &[
    "disallowed_origin",
    "unsupported_url",
    "unattributed_origin",
    "not_approved",
    "out_of_target_scope",
    "provider_unavailable",
    "invalid_protocol_value",
    "resource_budget_exhausted",
];

/// Validate one captured WebMCP result or authenticated Evidence envelope.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = request_object(input)?;
    reject_unknown_fields(request)?;

    if let Some(evidence) = request.get("evidence") {
        return project_evidence(evidence);
    }

    let capture = request
        .get("capture")
        .ok_or_else(|| invalid("capture or evidence is required"))?;

    if let Some(capture_object) = capture.as_object() {
        if capture_object.get("operation").is_some() && capture_object.get("evidence").is_some() {
            if capture_object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
                return Err(invalid("capture operation must be discover_webmcp_tools"));
            }
            return project_evidence(
                capture_object
                    .get("evidence")
                    .expect("checked evidence field"),
            );
        }
    }

    validate_result(capture)?;

    Ok(json!({
        "result": capture,
        "provenance": {
            "source": "caller-supplied-webmcp-observation",
            "execution": "none",
        },
    }))
}

/// Alias used by operation dispatchers that expose a generic handler name.
pub fn dispatch(input: &Value) -> Result<Value, Failure> {
    handle(input)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence serialization failed: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is malformed: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "Evidence operation does not match discover_webmcp_tools",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is malformed: {error}")))?;
    validate_result(&result)?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown",
        },
    }))
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("WebMCP capture result must be an object"))?;

    validate_browser(required_object(object, "browser")?)?;
    validate_target(required_object(object, "target")?)?;
    validate_status(object.get("status"))?;
    validate_tools(required_object(object, "tools")?)?;
    validate_completeness(required_object(object, "completeness")?)?;
    validate_string_array(object.get("limitations"), "limitations")?;

    Ok(())
}

fn validate_browser(browser: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["product", "protocol_version", "revision", "user_agent", "js_version"] {
        required_string(browser, field)?;
    }
    Ok(())
}

fn validate_target(target: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["target_id", "url", "origin"] {
        required_string(target, field)?;
    }
    Ok(())
}

fn validate_status(value: Option<&Value>) -> Result<(), Failure> {
    match value.and_then(Value::as_str) {
        Some("available" | "unavailable") => Ok(()),
        _ => Err(invalid("status must be available or unavailable")),
    }
}

fn validate_tools(tools: &Map<String, Value>) -> Result<(), Failure> {
    required_u64(tools, "total")?;
    let items = tools
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("tools.items must be an array"))?;

    for item in items {
        validate_tool(item)?;
    }

    Ok(())
}

fn validate_tool(value: &Value) -> Result<(), Failure> {
    let tool = value
        .as_object()
        .ok_or_else(|| invalid("each WebMCP tool must be an object"))?;
    let tool_key = required_string(tool, "tool_key")?;
    if !is_prefixed_digest(tool_key, "webmcp") {
        return Err(invalid("tool_key must be a webmcp-prefixed SHA-256 identifier"));
    }

    for field in [
        "name",
        "description",
        "frame_id",
        "frame_url",
        "owner_origin",
    ] {
        required_string(tool, field)?;
    }
    match required_string(tool, "declaration_kind")? {
        "declarative" | "imperative" => {}
        _ => return Err(invalid("declaration_kind is invalid")),
    }

    if let Some(schema) = tool.get("input_schema") {
        if !schema.is_null() {
            validate_json_value(schema)?;
        }
    } else {
        return Err(invalid("input_schema is required"));
    }
    validate_optional_digest(tool.get("input_schema_sha256"))?;
    validate_annotations(required_object(tool, "annotations")?)?;
    validate_registration_source(tool.get("registration_source"))?;
    if required_string(tool, "trust")? != "page-declared-untrusted" {
        return Err(invalid("trust must be page-declared-untrusted"));
    }

    Ok(())
}

fn validate_annotations(annotations: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["read_only", "untrusted_content", "autosubmit"] {
        validate_nullable_bool(annotations.get(field), field)?;
    }
    if let Some(value) = annotations.get("consequential") {
        validate_nullable_bool(Some(value), "consequential")?;
    }
    Ok(())
}

fn validate_registration_source(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Err(invalid("registration_source is required"));
    };
    if value.is_null() {
        return Ok(());
    }
    let source = value
        .as_object()
        .ok_or_else(|| invalid("registration_source must be an object or null"))?;
    required_string(source, "url")?;
    validate_optional_nonnegative_integer(source.get("line"), "line")?;
    validate_optional_nonnegative_integer(source.get("column"), "column")?;
    Ok(())
}

fn validate_completeness(completeness: &Map<String, Value>) -> Result<(), Failure> {
    match required_string(completeness, "status")? {
        "complete_within_window" | "policy_filtered" | "attach_limited" | "truncated" => {}
        _ => return Err(invalid("completeness.status is invalid")),
    }
    validate_enum_array(
        completeness.get("conditions"),
        &[
            "complete_within_window",
            "policy_filtered",
            "attach_limited",
            "truncated",
        ],
        "completeness.conditions",
        Some(3),
    )?;
    for field in [
        "policy_filtered_sections",
        "attach_limited_sections",
        "truncated_sections",
        "unavailable_sections",
    ] {
        validate_enum_array(completeness.get(field), BROWSER_SECTIONS, field, None)?;
    }
    validate_excluded(completeness.get("excluded"))?;
    validate_dropped_events(required_object(completeness, "dropped_events")?)?;
    Ok(())
}

fn validate_excluded(value: Option<&Value>) -> Result<(), Failure> {
    let excluded = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("completeness.excluded must be an array"))?;
    for item in excluded {
        let item = item
            .as_object()
            .ok_or_else(|| invalid("completeness.excluded entries must be objects"))?;
        if !BROWSER_SECTIONS.contains(&required_string(item, "section")?) {
            return Err(invalid("completeness.excluded.section is invalid"));
        }
        if !EXCLUSION_REASONS.contains(&required_string(item, "reason")?) {
            return Err(invalid("completeness.excluded.reason is invalid"));
        }
        if let Some(count) = item.get("count") {
            if !count.is_null() && count.as_u64().is_none() {
                return Err(invalid("completeness.excluded.count must be an integer or null"));
            }
        } else {
            return Err(invalid("completeness.excluded.count is required"));
        }
    }
    Ok(())
}

fn validate_dropped_events(events: &Map<String, Value>) -> Result<(), Failure> {
    for field in [
        "scripts",
        "network_requests",
        "console_events",
        "websocket_connections",
        "websocket_frames",
        "webmcp_tools",
        "timeline_events",
        "total",
    ] {
        required_u64(events, field)?;
    }
    Ok(())
}

fn validate_enum_array(
    value: Option<&Value>,
    allowed: &[&str],
    field: &str,
    maximum: Option<usize>,
) -> Result<(), Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.is_empty()
        || maximum.is_some_and(|maximum| values.len() > maximum)
        || values.iter().any(|item| {
        item.as_str()
            .map(|item| !allowed.contains(&item))
            .unwrap_or(true)
    }) {
        return Err(invalid(&format!("{field} contains an unsupported value")));
    }
    Ok(())
}

fn validate_string_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.iter().any(|item| item.as_str().is_none()) {
        return Err(invalid(&format!("{field} must contain only strings")));
    }
    Ok(())
}

fn validate_json_value(value: &Value) -> Result<(), Failure> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => Ok(()),
        Value::Array(values) => values.iter().try_for_each(validate_json_value),
        Value::Object(values) => values.values().try_for_each(validate_json_value),
    }
}

fn validate_optional_digest(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Err(invalid("input_schema_sha256 is required"));
    };
    if !value.is_null()
        && !value
            .as_str()
            .is_some_and(|value| is_prefixed_or_bare_digest(value, None))
    {
        return Err(invalid("input_schema_sha256 must be a digest or null"));
    }
    Ok(())
}

fn validate_nullable_bool(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    match value {
        Some(value) if value.is_null() || value.is_boolean() => Ok(()),
        Some(_) => Err(invalid(&format!("{field} must be a boolean or null"))),
        None => Err(invalid(&format!("{field} is required"))),
    }
}

fn validate_optional_nonnegative_integer(
    value: Option<&Value>,
    field: &str,
) -> Result<(), Failure> {
    match value {
        Some(value) if value.is_null() || value.as_u64().is_some() => Ok(()),
        Some(_) => Err(invalid(&format!("{field} must be an integer or null"))),
        None => Err(invalid(&format!("{field} is required"))),
    }
}

fn request_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
}

fn reject_unknown_fields(request: &Map<String, Value>) -> Result<(), Failure> {
    if request.keys().any(|key| !matches!(key.as_str(), "capture" | "evidence")) {
        return Err(invalid("input contains an unsupported field"));
    }
    if request.contains_key("capture") && request.contains_key("evidence") {
        return Err(invalid("supply either capture or evidence, not both"));
    }
    Ok(())
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

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
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

fn is_prefixed_digest(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(&format!("{prefix}_"))
        .is_some_and(|digest| digest.len() == 64 && is_lowercase_hex(digest))
}

fn is_prefixed_or_bare_digest(value: &str, prefix: Option<&str>) -> bool {
    prefix.map_or_else(
        || value.len() == 64 && is_lowercase_hex(value),
        |prefix| is_prefixed_digest(value, prefix),
    )
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
        "WebMCP capture is invalid.".into(),
        false,
        "Provide a complete captured WebMCP result or matching Evidence.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        "WebMCP Evidence is invalid.".into(),
        false,
        "Provide intact discover_webmcp_tools Evidence.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
