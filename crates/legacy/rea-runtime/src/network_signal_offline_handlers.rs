//! Offline handlers for packet, PCAP, signal, and historical web captures.
//!
//! The runtime owns dispatch only.  Acquisition belongs to a caller-owned
//! adapter: this module accepts decoded capture values, producer output, or
//! authenticated Evidence and delegates interpretation to application
//! producers.  It never opens paths, starts tools, opens sockets, or scans
//! hardware.

use rea_application::{pcap, pcap::packet_fields, signals, web};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Public operations handled by this isolated offline adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    InspectPacketFields,
    InspectPacketCapture,
    InspectPcapClient,
    InspectPcapCapture,
    InspectSignalDecoders,
    DecodeSignalRecording,
    InspectWebNetworkCapture,
}

impl Operation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "inspect_packet_fields" => Ok(Self::InspectPacketFields),
            "inspect_packet_capture" => Ok(Self::InspectPacketCapture),
            "inspect_pcap_client" => Ok(Self::InspectPcapClient),
            "inspect_pcap_capture" => Ok(Self::InspectPcapCapture),
            "inspect_signal_decoders" => Ok(Self::InspectSignalDecoders),
            "decode_signal_recording" => Ok(Self::DecodeSignalRecording),
            "inspect_web_network_capture" => Ok(Self::InspectWebNetworkCapture),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectPacketFields => "inspect_packet_fields",
            Self::InspectPacketCapture => "inspect_packet_capture",
            Self::InspectPcapClient => "inspect_pcap_client",
            Self::InspectPcapCapture => "inspect_pcap_capture",
            Self::InspectSignalDecoders => "inspect_signal_decoders",
            Self::DecodeSignalRecording => "decode_signal_recording",
            Self::InspectWebNetworkCapture => "inspect_web_network_capture",
        }
    }
}

/// The input authority promised by each offline contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAuthority {
    ToolOutput,
    Capture,
    EvidenceOrToolOutput,
}

/// Runtime metadata for callers that need to advertise these contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contract {
    pub operation: &'static str,
    pub authority: InputAuthority,
}

pub const CONTRACTS: [Contract; 7] = [
    Contract {
        operation: "inspect_packet_fields",
        authority: InputAuthority::ToolOutput,
    },
    Contract {
        operation: "inspect_packet_capture",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "inspect_pcap_client",
        authority: InputAuthority::ToolOutput,
    },
    Contract {
        operation: "inspect_pcap_capture",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "inspect_signal_decoders",
        authority: InputAuthority::ToolOutput,
    },
    Contract {
        operation: "decode_signal_recording",
        authority: InputAuthority::EvidenceOrToolOutput,
    },
    Contract {
        operation: "inspect_web_network_capture",
        authority: InputAuthority::EvidenceOrToolOutput,
    },
];

/// Dispatch a supported operation using only caller-supplied offline values.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(Operation::parse(operation)?, &input)
}

pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::InspectPacketFields => inspect_packet_fields(input),
        Operation::InspectPacketCapture => retain_tool_output(operation, input),
        Operation::InspectPcapCapture => pcap::capture::inspect(input),
        Operation::InspectPcapClient => pcap::client::inspect_value(input),
        Operation::InspectSignalDecoders => inspect_signal_decoders(input),
        Operation::DecodeSignalRecording => retain_offline_result(operation, input),
        Operation::InspectWebNetworkCapture => retain_web_capture(input),
    }
}

fn inspect_packet_fields(input: &Value) -> Result<Value, Failure> {
    let object = object_input(Operation::InspectPacketFields, input)?;
    if let Some(evidence) = object.get("evidence") {
        let projected = project_evidence(Operation::InspectPacketFields, evidence)?;
        validate_packet_fields_projection(&projected, object.get("request"))?;
        return Ok(projected);
    }
    let request = required_object(object, "request", Operation::InspectPacketFields)?;
    let glossary = object
        .get("tool_output")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid(
                Operation::InspectPacketFields,
                "tool_output must be a glossary string",
            )
        })?;
    let result = packet_fields::parse_glossary(&Value::Object(request.clone()), glossary)?;
    validate_packet_fields_result(&result, &Value::Object(request.clone()))?;
    Ok(json!({
        "result": result,
        "provenance": {"source": "caller-supplied-tshark-glossary", "execution": "none"}
    }))
}

fn validate_packet_fields_projection(
    projected: &Value,
    request: Option<&Value>,
) -> Result<(), Failure> {
    let result = projected.get("result").ok_or_else(|| {
        invalid(
            Operation::InspectPacketFields,
            "Evidence projection is missing result",
        )
    })?;
    if let Some(request) = request {
        validate_packet_fields_result(result, request)?;
    }
    Ok(())
}

fn validate_packet_fields_result(result: &Value, request: &Value) -> Result<(), Failure> {
    let result_object = result.as_object().ok_or_else(|| {
        invalid(
            Operation::InspectPacketFields,
            "Packet-field result must be an object",
        )
    })?;
    let selection = result_object.get("selection").ok_or_else(|| {
        invalid(
            Operation::InspectPacketFields,
            "Packet-field result is missing selection",
        )
    })?;
    let expected = normalized_packet_selection(request)?;
    if expected != selection.clone() {
        return Err(integrity(
            Operation::InspectPacketFields,
            "Captured selection does not match the requested selection",
        ));
    }
    if result_object
        .get("records")
        .and_then(Value::as_array)
        .is_none()
        || result_object
            .get("output_window")
            .and_then(Value::as_object)
            .is_none()
    {
        return Err(integrity(
            Operation::InspectPacketFields,
            "Packet-field result is missing records or output coverage",
        ));
    }
    Ok(())
}

fn normalized_packet_selection(request: &Value) -> Result<Value, Failure> {
    let object = request
        .as_object()
        .ok_or_else(|| invalid(Operation::InspectPacketFields, "request must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "protocol" | "query" | "offset" | "limit"
        ) {
            return Err(invalid(
                Operation::InspectPacketFields,
                "request contains an unknown field",
            ));
        }
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("protocols");
    if !matches!(kind, "protocols" | "fields") {
        return Err(invalid(
            Operation::InspectPacketFields,
            "request.kind must be protocols or fields",
        ));
    }
    let protocol = object.get("protocol").cloned().unwrap_or(Value::Null);
    if let Some(protocol_text) = protocol.as_str() {
        if protocol_text.is_empty() || protocol_text.len() > 8192 {
            return Err(invalid(
                Operation::InspectPacketFields,
                "request.protocol must be a non-empty string up to 8192 bytes",
            ));
        }
    } else if !protocol.is_null() {
        return Err(invalid(
            Operation::InspectPacketFields,
            "request.protocol must be a string or null",
        ));
    }
    let query = object.get("query").and_then(Value::as_str).unwrap_or("");
    if query.len() > 8192 || object.get("query").is_some_and(|value| !value.is_string()) {
        return Err(invalid(
            Operation::InspectPacketFields,
            "request.query must be a string up to 8192 bytes",
        ));
    }
    let offset = object.get("offset").and_then(Value::as_u64).unwrap_or(0);
    if object
        .get("offset")
        .is_some_and(|value| value.as_u64().is_none())
    {
        return Err(invalid(
            Operation::InspectPacketFields,
            "request.offset must be a nonnegative integer",
        ));
    }
    let limit = object.get("limit").cloned().unwrap_or_else(|| json!(50));
    if !limit.is_null() && (limit.as_u64().is_none() || limit.as_u64() == Some(0)) {
        return Err(invalid(
            Operation::InspectPacketFields,
            "request.limit must be positive or null",
        ));
    }
    Ok(json!({
        "kind": kind,
        "protocol": protocol,
        "query": query,
        "offset": offset,
        "limit": limit,
    }))
}

fn inspect_signal_decoders(input: &Value) -> Result<Value, Failure> {
    let object = object_input(Operation::InspectSignalDecoders, input)?;
    let request = required_object(object, "request", Operation::InspectSignalDecoders)?;
    let stdout = object
        .get("tool_output")
        .and_then(|value| value.get("stdout"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid(
                Operation::InspectSignalDecoders,
                "tool_output.stdout is required",
            )
        })?;
    let metadata = object
        .get("metadata")
        .cloned()
        .ok_or_else(|| invalid(Operation::InspectSignalDecoders, "metadata is required"))?;
    let metadata = serde_json::from_value(metadata)
        .map_err(|_| invalid(Operation::InspectSignalDecoders, "metadata is malformed"))?;
    signals::decoder_discovery::inspect(&Value::Object(request.clone()), stdout, metadata)
}

fn retain_offline_result(operation: Operation, input: &Value) -> Result<Value, Failure> {
    let object = object_input(operation, input)?;
    if let Some(evidence) = object.get("evidence") {
        return project_evidence(operation, evidence);
    }
    let result = object
        .get("tool_output")
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            invalid(
                operation,
                "supply authenticated evidence or object tool_output",
            )
        })?;
    Ok(json!({
        "result": result,
        "provenance": {"source": "caller-supplied-tool-output", "execution": "none"},
    }))
}

fn retain_tool_output(operation: Operation, input: &Value) -> Result<Value, Failure> {
    let object = object_input(operation, input)?;
    let output = object
        .get("tool_output")
        .filter(|value| value.is_array() || value.is_object())
        .cloned()
        .ok_or_else(|| invalid(operation, "tool_output must be a decoded packet result"))?;
    Ok(json!({
        "result": output,
        "provenance": {"source": "caller-supplied-tool-output", "execution": "none"},
    }))
}

fn retain_web_capture(input: &Value) -> Result<Value, Failure> {
    let operation = Operation::InspectWebNetworkCapture;
    let object = object_input(operation, input)?;
    if let Some(evidence) = object.get("evidence") {
        return project_evidence(operation, evidence);
    }
    let request = required_object(object, "request", operation)?;
    let capture = object
        .get("capture")
        .or_else(|| object.get("tool_output"))
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| {
            invalid(
                operation,
                "supply authenticated evidence, capture, or tool_output",
            )
        })?;
    web::network_capture::retain_result(&Value::Object(request.clone()), capture)
}

fn project_evidence(operation: Operation, value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(operation, &error.to_string()))?;
    let record =
        EvidenceRecord::parse(&raw).map_err(|error| integrity(operation, &error.to_string()))?;
    if !record.operation_matches(operation.name()) {
        return Err(integrity(
            operation,
            "Evidence operation does not match the requested operation",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(operation, &error.to_string()))?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

fn object_input<'a>(
    operation: Operation,
    input: &'a Value,
) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation, "input must be an object"))
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    operation: Operation,
) -> Result<&'a Map<String, Value>, Failure> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(operation, &format!("{field} must be an object")))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Offline network/signal operation is unknown: {name}"),
        false,
        "Select a supported offline capture operation.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn invalid(operation: Operation, reason: &str) -> Failure {
    Failure::new("invalid_request", "invalid_input", reason.into(), false, "Provide caller-supplied capture bytes, producer output, or authenticated Evidence; live acquisition is unsupported.".into(), BTreeMap::from([("operation", Detail::Text(operation.name().into())), ("authority", Detail::Text("offline_capture_only".into()))]))
}

fn integrity(operation: Operation, reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide authenticated, intact Evidence for the requested operation.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}
