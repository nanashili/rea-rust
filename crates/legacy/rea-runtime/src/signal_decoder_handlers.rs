//! Runtime boundary for the retained signal-decoder discovery result.
//!
//! The provider owns sigrok execution, executable identity, limits, and
//! Evidence creation.  This adapter only binds the public operation to the
//! application discovery producer using caller-supplied output and metadata.
//! It never starts sigrok, reads a recording, or scans hardware.

use rea_application::signals;
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// The retained operation exposed by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDecoderOperation {
    InspectSignalDecoders,
}

impl SignalDecoderOperation {
    /// Parse the stable public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            signals::decoder_discovery::OPERATION => Ok(Self::InspectSignalDecoders),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectSignalDecoders => signals::decoder_discovery::OPERATION,
        }
    }
}

/// Dispatch a retained signal-decoder operation by its public name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = SignalDecoderOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without contacting a provider.
pub fn dispatch_typed(operation: SignalDecoderOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        SignalDecoderOperation::InspectSignalDecoders => inspect_signal_decoders(input),
    }
}

fn inspect_signal_decoders(input: &Value) -> Result<Value, Failure> {
    let object = object_input(input)?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 {
            return Err(invalid("evidence input must contain only evidence"));
        }

        return project_evidence(evidence);
    }

    if let Some(capture) = object.get("capture") {
        let capture = capture
            .as_object()
            .ok_or_else(|| invalid("capture must be an object"))?;
        if object.len() != 1 {
            return Err(invalid("capture input must contain only capture"));
        }

        return inspect_captured(capture);
    }

    inspect_captured(object)
}

fn inspect_captured(object: &Map<String, Value>) -> Result<Value, Failure> {
    let allowed = ["request", "tool_output", "metadata"];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("input contains unknown field: {field}")));
    }

    let request = required_object(object, "request")?;
    let stdout = object
        .get("tool_output")
        .and_then(|value| value.get("stdout"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("tool_output.stdout is required"))?;
    let metadata = object
        .get("metadata")
        .cloned()
        .ok_or_else(|| invalid("metadata is required"))?;
    let metadata =
        serde_json::from_value(metadata).map_err(|_| invalid("metadata is malformed"))?;

    let report =
        signals::decoder_discovery::inspect(&Value::Object(request.clone()), stdout, metadata)?;
    Ok(json!({
        "result": report,
        "provenance": {
            "source": "caller-supplied-decoder-output",
            "execution": "none"
        }
    }))
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| integrity(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| integrity(&error.to_string()))?;
    if !record.operation_matches(signals::decoder_discovery::OPERATION) {
        return Err(integrity(
            "Evidence operation does not match inspect_signal_decoders",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&error.to_string()))?;
    serde_json::from_value::<signals::decoder_discovery::Report>(result.clone())
        .map_err(|error| integrity(&format!("normalized decoder report is malformed: {error}")))?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown"
        }
    }))
}

fn object_input(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
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

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Signal decoder operation is unknown: {name}"),
        false,
        "Select inspect_signal_decoders.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide the caller-supplied decoder request, producer output, and metadata.".into(),
        BTreeMap::from([
            (
                "operation".into(),
                Detail::Text(signals::decoder_discovery::OPERATION.into()),
            ),
            (
                "authority".into(),
                Detail::Text("caller-supplied-tool-output".into()),
            ),
        ]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide authenticated, intact Evidence for inspect_signal_decoders.".into(),
        BTreeMap::from([(
            "operation".into(),
            Detail::Text(signals::decoder_discovery::OPERATION.into()),
        )]),
    )
}
