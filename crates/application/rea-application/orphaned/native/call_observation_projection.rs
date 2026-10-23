//! Reducer for one captured `observe_native_calls` Evidence record.
//!
//! This boundary consumes retained observations only.  It never starts LLDB,
//! attaches to a process, instruments a target, or contacts a provider.  The
//! Evidence envelope remains intact so provider identity, lineage, limits, and
//! uncertainty are not lost when the result crosses the native boundary.

use rea_core::failure::{Detail, Failure};
use rea_core::evidence::record::EvidenceRecord;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "observe_native_calls";
const MAX_EVENTS: usize = 100_000;
const MAX_ITEMS: usize = 65_536;
const MAX_CAPTURE_BYTES: usize = 32 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;

/// Validate and retain one caller-supplied native call Evidence record.
pub fn observe_native_calls(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("observe_native_calls requires captured Evidence"))?;
    validate_evidence(evidence)?;
    Ok(evidence.clone())
}

/// Alias used by runtime adapters that expose application projections.
pub fn project(input: &Value) -> Result<Value, Failure> {
    observe_native_calls(input)
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let _ = observe_native_calls(input)?;
    Ok(())
}

fn validate_evidence(value: &Value) -> Result<(), Failure> {
    let evidence = object(value, "observe_native_calls Evidence")?;

    authenticate_evidence(value)?;

    if evidence.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("Evidence operation must be observe_native_calls"));
    }
    require_non_empty_string(evidence.get("evidence_id"), "Evidence.evidence_id")?;

    for field in [
        "provider",
        "predicate_type",
        "parameters",
        "raw_result",
        "normalized_result",
        "confidence",
        "authority",
        "environment",
        "limitations",
        "relationship_coverage",
        "locations",
        "evidence_links",
    ] {
        if !evidence.contains_key(field) {
            return Err(invalid(&format!("Evidence requires {field}")));
        }
    }

    validate_provider(evidence.get("provider"))?;
    require_non_empty_string(evidence.get("predicate_type"), "Evidence.predicate_type")?;
    validate_object_field(evidence.get("parameters"), "Evidence.parameters")?;
    if !matches!(
        evidence.get("confidence").and_then(Value::as_str),
        Some("observed" | "derived" | "inferred")
    ) {
        return Err(invalid("Evidence.confidence is invalid"));
    }
    if !matches!(
        evidence.get("authority").and_then(Value::as_str),
        Some("shipped-artifact" | "controlled-replay" | "historical-reference" | "external-service" | "analyst-inference")
    ) {
        return Err(invalid("Evidence.authority is invalid"));
    }
    validate_nullable_container(evidence.get("subject"), "Evidence.subject")?;
    validate_nullable_container(evidence.get("analysis_profile"), "Evidence.analysis_profile")?;
    validate_nullable_container(evidence.get("environment"), "Evidence.environment")?;
    validate_evidence_locations(evidence.get("locations"))?;
    validate_string_array(evidence.get("evidence_links"), "Evidence.evidence_links")?;

    for field in ["provider", "subject", "parameters", "lineage"] {
        if let Some(value) = evidence.get(field) {
            if !value.is_object() && !value.is_array() && !value.is_string() && !value.is_null() {
                return Err(invalid(&format!("Evidence.{field} has an invalid shape")));
            }
        }
    }
    validate_limitations(evidence.get("limitations"), "Evidence.limitations")?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("Evidence must include normalized_result or result"))?;
    validate_result(result)
}

/// Verify the provider-neutral Evidence identity before trusting its payload.
///
/// The shape checks below provide operation-specific diagnostics, while
/// `EvidenceRecord::parse` owns canonicalization and semantic-id validation.
/// Keeping both layers avoids accepting a well-shaped but forged observation.
fn authenticate_evidence(value: &Value) -> Result<(), Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(&format!("Evidence cannot be serialized: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("Evidence is not authenticated: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid("Evidence operation must be observe_native_calls"));
    }
    Ok(())
}

fn validate_provider(value: Option<&Value>) -> Result<(), Failure> {
    let provider = object(value.ok_or_else(|| invalid("Evidence.provider is required"))?, "Evidence.provider")?;
    require_non_empty_string(provider.get("id"), "provider.id")?;
    require_non_empty_string(provider.get("name"), "provider.name")?;
    validate_nullable_string(provider.get("version"), "provider.version")
}

fn validate_object_field(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    object(value.ok_or_else(|| invalid(&format!("{field} is required")))?, field).map(|_| ())
}

fn validate_nullable_container(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let Some(value) = value else {
        return Err(invalid(&format!("{field} is required")));
    };
    if value.is_null() || value.is_object() { Ok(()) } else { Err(invalid(&format!("{field} must be an object or null"))) }
}

fn validate_evidence_locations(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in bounded_array(value, "Evidence.locations")?.iter().enumerate() {
        let location = object(item, &format!("Evidence.locations[{index}]"))?;
        match location.get("kind").and_then(Value::as_str) {
            Some("address") => require_non_empty_string(location.get("address"), "Evidence location.address")?,
            Some("address-range") => {
                require_non_empty_string(location.get("start"), "Evidence location.start")?;
                require_non_empty_string(location.get("end"), "Evidence location.end")?;
            }
            Some("artifact-path") => require_non_empty_string(location.get("path"), "Evidence location.path")?,
            Some("file-offset") => require_nonnegative_integer(location.get("offset"), "Evidence location.offset")?,
            Some("file-offset-range") => {
                require_nonnegative_integer(location.get("start"), "Evidence location.start")?;
                require_nonnegative_integer(location.get("end"), "Evidence location.end")?;
            }
            _ => return Err(invalid("Evidence location.kind is invalid")),
        }
    }
    Ok(())
}

fn validate_result(value: &Value) -> Result<(), Failure> {
    let object = object(value, "native call observation result")?;
    reject_unknown_fields(object, "native call observation result", ["target", "debugger", "process", "breakpoints", "events", "coverage", "limitations"])?;
    if serde_json::to_vec(value).map_or(true, |bytes| bytes.len() > MAX_CAPTURE_BYTES) {
        return Err(resource("native call observation exceeds the capture limit"));
    }
    validate_target(object.get("target"))?;
    validate_debugger(object.get("debugger"))?;
    validate_process(object.get("process"))?;
    validate_breakpoints(object.get("breakpoints"))?;
    validate_events(object.get("events"))?;
    validate_coverage(object.get("coverage"))?;
    validate_limitations(object.get("limitations"), "native call limitations")
}

fn validate_target(value: Option<&Value>) -> Result<(), Failure> {
    let target = object(value.ok_or_else(|| invalid("native call result requires target"))?, "target")?;
    reject_unknown_fields(target, "target", ["path", "sha256", "architecture", "arguments", "environment", "working_directory", "launch_identity"])?;
    for field in ["path", "sha256", "architecture", "arguments", "environment", "working_directory", "launch_identity"] {
        if !target.contains_key(field) { return Err(invalid(&format!("target requires {field}"))); }
    }
    require_string(target.get("path"), "target.path")?;
    require_hex_digest(target.get("sha256"), "target.sha256")?;
    require_string(target.get("architecture"), "target.architecture")?;
    validate_string_array(target.get("arguments"), "target.arguments")?;
    validate_string_map(target.get("environment"), "target.environment")?;
    validate_nullable_string(target.get("working_directory"), "target.working_directory")?;
    let identity = object(target.get("launch_identity").unwrap(), "target.launch_identity")?;
    reject_unknown_fields(identity, "target.launch_identity", ["loaded_image_sha256", "file_device", "file_inode", "selected_file_sha256", "module_path", "module_uuid", "stable"])?;
    for field in ["loaded_image_sha256", "file_device", "file_inode", "selected_file_sha256", "module_path", "module_uuid", "stable"] {
        if !identity.contains_key(field) { return Err(invalid(&format!("launch_identity requires {field}"))); }
    }
    if identity.get("loaded_image_sha256") != Some(&Value::Null) { return Err(invalid("loaded_image_sha256 must remain unknown")); }
    for field in ["file_device", "file_inode", "selected_file_sha256", "module_path", "module_uuid"] { validate_nullable_string(identity.get(field), field)?; }
    if identity.get("selected_file_sha256") != Some(&Value::Null) { require_hex_digest(identity.get("selected_file_sha256"), "selected_file_sha256")?; }
    require_bool(identity.get("stable"), "launch_identity.stable")
}

fn validate_debugger(value: Option<&Value>) -> Result<(), Failure> {
    let debugger = object(value.ok_or_else(|| invalid("native call result requires debugger"))?, "debugger")?;
    reject_unknown_fields(debugger, "debugger", ["path", "sha256", "version"])?;
    require_string(debugger.get("path"), "debugger.path")?;
    require_hex_digest(debugger.get("sha256"), "debugger.sha256")?;
    validate_nullable_string(debugger.get("version"), "debugger.version")
}

fn validate_process(value: Option<&Value>) -> Result<(), Failure> {
    let process = object(value.ok_or_else(|| invalid("native call result requires process"))?, "process")?;
    reject_unknown_fields(process, "process", ["pid", "outcome", "exit_status", "exit_description", "terminated", "elapsed_ms", "stdout", "stderr", "other_stops"])?;
    require_positive_integer(process.get("pid"), "process.pid")?;
    let outcome = process.get("outcome").and_then(Value::as_str).ok_or_else(|| invalid("process.outcome must be text"))?;
    if !matches!(outcome, "exited" | "duration-elapsed" | "event-limit" | "stop-limit" | "resource-limit") { return Err(invalid("process.outcome is invalid")); }
    validate_nullable_integer(process.get("exit_status"), "process.exit_status")?;
    validate_nullable_string(process.get("exit_description"), "process.exit_description")?;
    require_bool(process.get("terminated"), "process.terminated")?;
    require_nonnegative_number(process.get("elapsed_ms"), "process.elapsed_ms")?;
    validate_output(process.get("stdout"), "process.stdout")?;
    validate_output(process.get("stderr"), "process.stderr")?;
    validate_string_array(process.get("other_stops"), "process.other_stops")
}

fn validate_output(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let output = object(value.ok_or_else(|| invalid(&format!("{field} is required")))?, field)?;
    reject_unknown_fields(output, field, ["text", "bytes", "truncated", "complete"])?;
    require_string(output.get("text"), &format!("{field}.text"))?;
    if output.get("text").and_then(Value::as_str).map_or(0, str::len) > MAX_TEXT_BYTES { return Err(resource(&format!("{field}.text exceeds the output limit"))); }
    require_nonnegative_integer(output.get("bytes"), &format!("{field}.bytes"))?;
    require_bool(output.get("truncated"), &format!("{field}.truncated"))?;
    require_bool(output.get("complete"), &format!("{field}.complete"))
}

fn validate_breakpoints(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in bounded_array(value, "breakpoints")?.iter().enumerate() {
        let breakpoint = object(item, &format!("breakpoints[{index}]"))?;
        reject_unknown_fields(breakpoint, &format!("breakpoints[{index}]"), ["index", "request", "location_count", "locations"])?;
        require_nonnegative_integer(breakpoint.get("index"), "breakpoint.index")?;
        validate_request(breakpoint.get("request"))?;
        require_nonnegative_integer(breakpoint.get("location_count"), "breakpoint.location_count")?;
        validate_locations(breakpoint.get("locations"), "breakpoint.locations")?;
    }
    Ok(())
}

fn validate_request(value: Option<&Value>) -> Result<(), Failure> {
    let request = object(value.ok_or_else(|| invalid("breakpoint.request is required"))?, "breakpoint.request")?;
    match request.get("kind").and_then(Value::as_str) {
        Some("function") => {
            reject_unknown_fields(request, "breakpoint.request", ["kind", "name", "module"])?;
            require_non_empty_string(request.get("name"), "breakpoint.name")?;
            validate_nullable_string(request.get("module"), "breakpoint.module")
        }
        Some("objc-method") => {
            reject_unknown_fields(request, "breakpoint.request", ["kind", "selector", "class_name", "method_type"])?;
            require_non_empty_string(request.get("selector"), "breakpoint.selector")?;
            validate_nullable_string(request.get("class_name"), "breakpoint.class_name")?;
            if !matches!(request.get("method_type").and_then(Value::as_str), Some("instance" | "class" | "any")) { return Err(invalid("breakpoint.method_type is invalid")); }
            Ok(())
        }
        _ => Err(invalid("breakpoint.kind is invalid")),
    }
}

fn validate_locations(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for item in bounded_array(value, field)? {
        reject_unknown_fields(object(item, field)?, field, ["load_address", "file_address", "module", "module_path", "symbol"])?;
        validate_location(item, field)?;
    }
    Ok(())
}

fn validate_location(value: &Value, field: &str) -> Result<(), Failure> {
    let location = object(value, field)?;
    require_hex(location.get("load_address"), "location.load_address")?;
    validate_nullable_string(location.get("file_address"), "location.file_address")?;
    if location.get("file_address") != Some(&Value::Null) { require_hex(location.get("file_address"), "location.file_address")?; }
    for name in ["module", "module_path", "symbol"] { validate_nullable_string(location.get(name), &format!("location.{name}"))?; }
    Ok(())
}

fn validate_events(value: Option<&Value>) -> Result<(), Failure> {
    let events = bounded_array(value, "events")?;
    if events.len() > MAX_EVENTS { return Err(resource("native call events exceed the event limit")); }
    for (index, item) in events.iter().enumerate() {
        let event = object(item, &format!("events[{index}]"))?;
        reject_unknown_fields(event, &format!("events[{index}]"), ["sequence", "elapsed_ms", "thread_id", "breakpoint_index", "load_address", "file_address", "module", "module_path", "symbol", "receiver_class", "selector", "registers", "backtrace"])?;
        for field in ["sequence", "elapsed_ms", "thread_id", "breakpoint_index", "load_address", "file_address", "module", "module_path", "symbol", "receiver_class", "selector", "registers", "backtrace"] {
            if !event.contains_key(field) { return Err(invalid(&format!("event requires {field}"))); }
        }
        require_nonnegative_integer(event.get("sequence"), "event.sequence")?;
        require_nonnegative_number(event.get("elapsed_ms"), "event.elapsed_ms")?;
        require_nonnegative_integer(event.get("thread_id"), "event.thread_id")?;
        require_nonnegative_integer(event.get("breakpoint_index"), "event.breakpoint_index")?;
        validate_location(item, "event")?;
        validate_nullable_string(event.get("receiver_class"), "event.receiver_class")?;
        validate_nullable_string(event.get("selector"), "event.selector")?;
        for register in bounded_array(event.get("registers"), "event.registers")? { let register = object(register, "event.register")?; reject_unknown_fields(register, "event.register", ["name", "value"])?; require_string(register.get("name"), "register.name")?; require_hex(register.get("value"), "register.value")?; }
        validate_locations(event.get("backtrace"), "event.backtrace")?;
    }
    Ok(())
}

fn validate_coverage(value: Option<&Value>) -> Result<(), Failure> {
    let coverage = object(value.ok_or_else(|| invalid("native call result requires coverage"))?, "coverage")?;
    reject_unknown_fields(coverage, "coverage", ["status", "event_limit_reached", "resource_limit_reached", "breakpoint_locations_truncated", "unresolved_breakpoints"])?;
    if !matches!(coverage.get("status").and_then(Value::as_str), Some("complete" | "partial")) { return Err(invalid("coverage.status is invalid")); }
    require_bool(coverage.get("event_limit_reached"), "coverage.event_limit_reached")?;
    require_bool(coverage.get("resource_limit_reached"), "coverage.resource_limit_reached")?;
    if let Some(value) = coverage.get("breakpoint_locations_truncated") { require_bool(Some(value), "coverage.breakpoint_locations_truncated")?; }
    for item in bounded_array(coverage.get("unresolved_breakpoints"), "coverage.unresolved_breakpoints")? { require_nonnegative_integer(Some(item), "coverage.unresolved_breakpoints entry")?; }
    Ok(())
}

fn validate_limitations(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for item in bounded_array(value, field)? { require_string(Some(item), field)?; }
    Ok(())
}

fn bounded_array<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a Vec<Value>, Failure> {
    let values = value.and_then(Value::as_array).ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.len() > MAX_ITEMS { return Err(resource(&format!("{field} exceeds its item limit"))); }
    Ok(values)
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, Failure> { value.as_object().ok_or_else(|| invalid(&format!("{field} must be an object"))) }
fn reject_unknown_fields<const N: usize>(object: &Map<String, Value>, field: &str, allowed: [&str; N]) -> Result<(), Failure> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(&format!("{field} contains unknown field {key}")));
        }
    }
    Ok(())
}
fn require_string(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_str).is_none() { Err(invalid(&format!("{field} must be text"))) } else { Ok(()) } }
fn require_non_empty_string(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_str).map_or(true, str::is_empty) { Err(invalid(&format!("{field} must be non-empty text"))) } else { Ok(()) } }
fn validate_nullable_string(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value == Some(&Value::Null) { Ok(()) } else { require_string(value, field) } }
fn require_bool(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_bool).is_none() { Err(invalid(&format!("{field} must be boolean"))) } else { Ok(()) } }
fn require_nonnegative_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_u64).is_none() { Err(invalid(&format!("{field} must be a non-negative integer"))) } else { Ok(()) } }
fn require_positive_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_u64).is_none_or(|value| value == 0) { Err(invalid(&format!("{field} must be positive"))) } else { Ok(()) } }
fn validate_nullable_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value == Some(&Value::Null) { Ok(()) } else { require_integer(value, field) } }
fn require_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_i64).is_none() { Err(invalid(&format!("{field} must be an integer"))) } else { Ok(()) } }
fn require_nonnegative_number(value: Option<&Value>, field: &str) -> Result<(), Failure> { if value.and_then(Value::as_f64).map_or(true, |value| value < 0.0 || !value.is_finite()) { Err(invalid(&format!("{field} must be non-negative"))) } else { Ok(()) } }
fn require_hex(value: Option<&Value>, field: &str) -> Result<(), Failure> { let text = value.and_then(Value::as_str).ok_or_else(|| invalid(&format!("{field} must be hexadecimal text")))?; if !text.starts_with("0x") || text.len() <= 2 || !text[2..].bytes().all(|byte| byte.is_ascii_hexdigit()) { return Err(invalid(&format!("{field} must use canonical hexadecimal form"))); } Ok(()) }
fn require_hex_digest(value: Option<&Value>, field: &str) -> Result<(), Failure> { let text = value.and_then(Value::as_str).ok_or_else(|| invalid(&format!("{field} must be a SHA-256 digest")))?; if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) { return Err(invalid(&format!("{field} must be a lowercase SHA-256 digest"))); } Ok(()) }
fn validate_string_array(value: Option<&Value>, field: &str) -> Result<(), Failure> { for item in bounded_array(value, field)? { require_string(Some(item), field)?; } Ok(()) }
fn validate_string_map(value: Option<&Value>, field: &str) -> Result<(), Failure> { let map = object(value.ok_or_else(|| invalid(&format!("{field} must be an object")))?, field)?; if map.len() > MAX_ITEMS { return Err(resource(&format!("{field} exceeds its item limit"))); } for item in map.values() { require_string(Some(item), field)?; } Ok(()) }
fn invalid(reason: &str) -> Failure { Failure::new("invalid_request", "invalid_input", reason.into(), false, "Provide captured observe_native_calls Evidence and retry.".into(), BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))])) }
fn resource(reason: &str) -> Failure { Failure::new("resource_constraint", "resource_constraint", reason.into(), false, "Reduce the retained native call observation and retry.".into(), BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))])) }
