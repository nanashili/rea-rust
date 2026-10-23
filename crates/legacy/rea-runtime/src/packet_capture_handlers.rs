//! Isolated runtime boundary for `inspect_packet_capture`.
//!
//! This operation is the field-oriented TShark workflow.  It is deliberately
//! separate from `inspect_pcap_capture`, whose application producer builds a
//! whole-capture inventory from caller-supplied decoded records.  The native
//! runtime does not own a TShark 4.x plus `prlimit` provider, so this adapter
//! validates the public request and fails closed without pretending that a
//! pcap inventory is a packet-field inspection.

use base64::Engine;
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

pub const OPERATION: &str = "inspect_packet_capture";

/// The only operation owned by this isolated adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    InspectPacketCapture,
}

impl Operation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            OPERATION => Ok(Self::InspectPacketCapture),
            _ => Err(invalid_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectPacketCapture => OPERATION,
        }
    }
}

/// Runtime metadata for the public contract.  The adapter accepts a capture
/// request but grants no live-capture, device, or provider authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAuthority {
    Capture,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contract {
    pub operation: &'static str,
    pub authority: InputAuthority,
}

pub const CONTRACT: Contract = Contract {
    operation: OPERATION,
    authority: InputAuthority::Capture,
};

/// Validate the exact public request, then fail closed because the native
/// runtime has no TShark provider.  The raw request is retained in failure
/// details so caller-selected fields, filters, paging, and pass mode survive
/// the unavailable-provider boundary unchanged.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(Operation::parse(operation)?, &input)
}

pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    if let Some(object) = input.as_object() {
        if let Some(evidence) = object.get("evidence") {
            if object.len() != 1 {
                return Err(invalid_capture(
                    "evidence cannot be combined with another capture representation",
                ));
            }
            return project_evidence(evidence);
        }
        if let Some(capture) = object.get("capture") {
            return project_capture(capture);
        }
    }
    validate_request(operation, input)?;
    Err(provider_unavailable(operation, input))
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence serialization failed: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is malformed: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "Evidence operation does not match inspect_packet_capture",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is malformed: {error}")))?;
    validate_result(&result)?;
    Ok(serde_json::json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"}
    }))
}

fn project_capture(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_capture("capture must be an object"))?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "result" | "normalized_result" | "bytes_base64"
        )
    }) {
        return Err(invalid_capture("capture contains unsupported fields"));
    }
    if object.contains_key("result") && object.contains_key("normalized_result") {
        return Err(invalid_capture(
            "capture must contain only one result representation",
        ));
    }
    let result = object
        .get("result")
        .or_else(|| object.get("normalized_result"))
        .ok_or_else(|| {
            invalid_capture("capture requires a captured result or authenticated Evidence")
        })?;
    let result = result
        .as_object()
        .ok_or_else(|| invalid_capture("captured result must be an object"))?;
    if let Some(encoded) = object.get("bytes_base64") {
        let encoded = encoded
            .as_str()
            .ok_or_else(|| invalid_capture("bytes_base64 must be a string"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid_capture("bytes_base64 is malformed"))?;
        let artifact = result
            .get("artifact")
            .and_then(Value::as_object)
            .ok_or_else(|| integrity("captured result omitted artifact identity"))?;
        let expected = sha256(&bytes);
        if artifact.get("sha256").and_then(Value::as_str) != Some(expected.as_str())
            || artifact.get("bytes").and_then(Value::as_u64) != Some(bytes.len() as u64)
        {
            return Err(integrity(
                "captured bytes do not match result artifact identity",
            ));
        }
    }
    let result = Value::Object(result.clone());
    validate_result(&result)?;
    Ok(serde_json::json!({
        "result": result,
        "provenance": {"source": "caller-supplied-capture", "execution": "none"}
    }))
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| integrity("packet result must be an object"))?;
    let artifact = object
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("packet result omitted artifact"))?;
    let path = artifact
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty() && !path.contains('\0'))
        .ok_or_else(|| integrity("packet artifact path is invalid"))?;
    if !Path::new(path).is_absolute() {
        return Err(integrity("packet artifact path must be absolute"));
    }
    let digest = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(integrity("packet artifact sha256 is invalid"));
    }
    let selection = object
        .get("selection")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("packet result omitted selection"))?;
    if selection.get("path").and_then(Value::as_str) != Some(path) {
        return Err(integrity("packet selection changed the artifact path"));
    }
    let packets = object
        .get("packets")
        .and_then(Value::as_array)
        .ok_or_else(|| integrity("packet result omitted packets"))?;
    let output = object
        .get("output_window")
        .and_then(Value::as_object)
        .ok_or_else(|| integrity("packet result omitted output window"))?;
    let matching = output
        .get("matching_packets")
        .and_then(Value::as_u64)
        .ok_or_else(|| integrity("packet output window is invalid"))?;
    let offset = selection
        .get("match_offset")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let remaining = matching.saturating_sub(offset);
    let expected = match selection.get("match_limit") {
        Some(Value::Null) => remaining,
        Some(value) => remaining.min(
            value
                .as_u64()
                .ok_or_else(|| integrity("packet match_limit is invalid"))?,
        ),
        None => remaining.min(50),
    };
    if packets.len() as u64 != expected
        || output.get("returned_packets").and_then(Value::as_u64) != Some(expected)
    {
        return Err(integrity("packet output window does not match selection"));
    }
    if output.get("has_more").and_then(Value::as_bool) != Some(remaining > expected) {
        return Err(integrity("packet output continuation flag is invalid"));
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide an intact captured packet result or authenticated Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_capture(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a captured packet result or authenticated Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn validate_request(operation: Operation, input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_for(operation, "request must be an object"))?;

    let allowed = [
        "path",
        "fields",
        "display_filter",
        "decode_as",
        "packet_limit",
        "two_pass",
        "match_offset",
        "match_limit",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid_for(
            operation,
            "request contains fields outside the public inspect_packet_capture schema",
        ));
    }

    let path = required_string(object, "path", operation)?;
    if !Path::new(path).is_absolute() {
        return Err(invalid_for(
            operation,
            "path must be an absolute local path",
        ));
    }

    let fields = object
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_for(operation, "fields must be a non-empty array"))?;
    if fields.is_empty() || fields.len() > 1024 {
        return Err(invalid_for(
            operation,
            "fields must contain between one and 1024 entries",
        ));
    }
    for field in fields {
        validate_argument(field, "fields", operation)?;
    }

    if let Some(filter) = object.get("display_filter") {
        if !filter.is_null() {
            validate_argument(filter, "display_filter", operation)?;
        }
    }
    if let Some(decode_as) = object.get("decode_as") {
        let values = decode_as
            .as_array()
            .ok_or_else(|| invalid_for(operation, "decode_as must be an array"))?;
        if values.len() > 1024 {
            return Err(invalid_for(operation, "decode_as has too many entries"));
        }
        for value in values {
            validate_argument(value, "decode_as", operation)?;
        }
    }

    validate_positive_integer(
        object.get("packet_limit"),
        "packet_limit",
        operation,
        true,
        Some(i32::MAX as u64),
    )?;
    if let Some(two_pass) = object.get("two_pass") {
        if !two_pass.is_boolean() {
            return Err(invalid_for(operation, "two_pass must be a boolean"));
        }
    }
    validate_nonnegative_integer(object.get("match_offset"), "match_offset", operation)?;
    validate_positive_integer(
        object.get("match_limit"),
        "match_limit",
        operation,
        true,
        None,
    )?;

    if selector_bytes(object) > 32 * 1024 {
        return Err(invalid_for(
            operation,
            "packet selectors exceed the 32 KiB encoded argument budget",
        ));
    }

    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    operation: Operation,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| invalid_for(operation, &format!("{field} must be a non-empty string")))
}

fn validate_argument(value: &Value, field: &str, operation: Operation) -> Result<(), Failure> {
    let argument = value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 8192 && !value.contains('\0'))
        .ok_or_else(|| invalid_for(operation, &format!("{field} contains an invalid argument")))?;
    let _ = argument;
    Ok(())
}

fn validate_nonnegative_integer(
    value: Option<&Value>,
    field: &str,
    operation: Operation,
) -> Result<(), Failure> {
    if let Some(value) = value {
        if value.as_u64().is_none() {
            return Err(invalid_for(
                operation,
                &format!("{field} must be a nonnegative integer"),
            ));
        }
    }
    Ok(())
}

fn validate_positive_integer(
    value: Option<&Value>,
    field: &str,
    operation: Operation,
    nullable: bool,
    maximum: Option<u64>,
) -> Result<(), Failure> {
    if let Some(value) = value {
        if nullable && value.is_null() {
            return Ok(());
        }
        let number = value.as_u64().filter(|number| *number > 0);
        let Some(number) = number else {
            return Err(invalid_for(
                operation,
                &format!("{field} must be a positive integer or null"),
            ));
        };
        if maximum.is_some_and(|maximum| number > maximum) {
            return Err(invalid_for(
                operation,
                &format!("{field} exceeds its public maximum"),
            ));
        }
    }
    Ok(())
}

fn selector_bytes(object: &Map<String, Value>) -> usize {
    let field_bytes = object
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| value.len() + 20)
        .sum::<usize>();
    let decode_as_bytes = object
        .get("decode_as")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|value| value.len() + 20)
        .sum::<usize>();
    let filter_bytes = object
        .get("display_filter")
        .and_then(Value::as_str)
        .map_or(0, |value| value.len() + 20);
    field_bytes
        .saturating_add(decode_as_bytes)
        .saturating_add(filter_bytes)
}

fn provider_unavailable(operation: Operation, input: &Value) -> Failure {
    let mut details = BTreeMap::from([
        ("operation", Detail::Text(operation.name().into())),
        ("provider", Detail::Text("tshark-capture".into())),
        (
            "reason",
            Detail::Text("native runtime has no TShark 4.x/prlimit provider".into()),
        ),
    ]);
    if let Some(path) = input.get("path").and_then(Value::as_str) {
        details.insert("source_path", Detail::Text(path.into()));
    }
    if let Ok(raw) = serde_json::value::to_raw_value(input) {
        details.insert("user_input", Detail::Raw(raw));
    }
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        "inspect_packet_capture requires the caller-selected TShark 4.x provider on Linux.".into(),
        true,
        "Run the request through the TShark capture provider; no pcap inventory is substituted."
            .into(),
        details,
    )
}

fn invalid_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("unsupported offline packet-capture operation: {name}"),
        false,
        "Use inspect_packet_capture with its public request schema.".into(),
        BTreeMap::new(),
    )
}

fn invalid_for(operation: Operation, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide path, fields, and the documented optional packet-selection controls.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}
