//! Offline dispatch for firmware and artifact workflow projections.
//!
//! Provider adapters own target reads, command execution, and Evidence
//! creation.  This adapter accepts only bounded caller-supplied reports or
//! complete Evidence.  It never invokes an extractor, publishes files, or
//! executes extracted content.  The module is intentionally not registered
//! with the shared MCP server until the migration boundary is approved.

use rea_application::{
    apple::signature_inspection, artifacts, artifacts::desktop_application, firmware,
};
use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::BTreeMap;

/// Offline workflow names covered by this isolated adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArtifactWorkflowOperation {
    InspectFirmwareRegions,
    ExtractFirmware,
    InspectArtifact,
    ExtractArtifact,
    CompareArtifacts,
    InspectSignature,
    InspectDesktopApplication,
}

impl ArtifactWorkflowOperation {
    /// Parse the stable public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            firmware::regions::OPERATION => Ok(Self::InspectFirmwareRegions),
            firmware::extraction::OPERATION => Ok(Self::ExtractFirmware),
            "inspect_artifact" => Ok(Self::InspectArtifact),
            artifacts::extraction::OPERATION => Ok(Self::ExtractArtifact),
            artifacts::compare::OPERATION => Ok(Self::CompareArtifacts),
            signature_inspection::OPERATION => Ok(Self::InspectSignature),
            "inspect_desktop_application" => Ok(Self::InspectDesktopApplication),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectFirmwareRegions => firmware::regions::OPERATION,
            Self::ExtractFirmware => firmware::extraction::OPERATION,
            Self::InspectArtifact => "inspect_artifact",
            Self::ExtractArtifact => artifacts::extraction::OPERATION,
            Self::CompareArtifacts => artifacts::compare::OPERATION,
            Self::InspectSignature => signature_inspection::OPERATION,
            Self::InspectDesktopApplication => "inspect_desktop_application",
        }
    }
}

/// Dispatch one workflow from caller-supplied offline observations.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = ArtifactWorkflowOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed operation without contacting a provider.
pub fn dispatch_typed(
    operation: ArtifactWorkflowOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        ArtifactWorkflowOperation::InspectFirmwareRegions => inspect_firmware_regions(input),
        ArtifactWorkflowOperation::ExtractFirmware => extract_firmware(input),
        ArtifactWorkflowOperation::InspectArtifact => inspect_artifact(input),
        ArtifactWorkflowOperation::ExtractArtifact => artifacts::extraction::inspect(input),
        ArtifactWorkflowOperation::CompareArtifacts => {
            artifacts::compare::compare(input, None, &Cancellation::default()).map(raw_value)
        }
        ArtifactWorkflowOperation::InspectSignature => {
            signature_inspection::inspect(input).map(raw_value)
        }
        ArtifactWorkflowOperation::InspectDesktopApplication => desktop_application::project(input),
    }
}

fn inspect_firmware_regions(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, firmware::regions::OPERATION)?;
    let path = required_string(object, "path", firmware::regions::OPERATION)?;
    let input_size = object
        .get("input_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(firmware::regions::OPERATION, "input_size is required"))?;
    let report = object
        .get("report")
        .ok_or_else(|| invalid(firmware::regions::OPERATION, "report is required"))?;
    let engine = object
        .get("engine")
        .ok_or_else(|| invalid(firmware::regions::OPERATION, "engine is required"))?;
    firmware::regions::normalize_report(path, input_size as usize, report, engine).map(raw_value)
}

fn extract_firmware(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, firmware::extraction::OPERATION)?;
    let request = object
        .get("request")
        .ok_or_else(|| invalid(firmware::extraction::OPERATION, "request is required"))?;
    let report = object
        .get("report")
        .ok_or_else(|| invalid(firmware::extraction::OPERATION, "report is required"))?;

    // The application producer may read the caller-selected immutable source
    // to bind reported bytes, but it never creates output or invokes a tool.
    firmware::extraction::extract(request, report)
}

fn inspect_artifact(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, "inspect_artifact")?;
    let evidence = object
        .get("evidence")
        .ok_or_else(|| invalid("inspect_artifact", "complete Evidence is required"))?;
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid("inspect_artifact", &error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid("inspect_artifact", &error.to_string()))?;
    if !record.operation_matches("inspect_artifact")
        && !record.operation_matches("inventory_artifact")
    {
        return Err(invalid(
            "inspect_artifact",
            "Evidence operation must be inspect_artifact or inventory_artifact",
        ));
    }
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid("inspect_artifact", &error.to_string()))?;
    if record.operation_matches("inventory_artifact") {
        return artifacts::inventory_evidence::normalize_result(normalized)
            .map_err(|error| invalid("inspect_artifact", &error));
    }
    Ok(normalized)
}

fn input_object<'a>(
    input: &'a Value,
    operation: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation, "input must be an object"))
}

fn required_string<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    operation: &'static str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(operation, &format!("{field} is required")))
}

fn raw_value(raw: Box<serde_json::value::RawValue>) -> Value {
    serde_json::from_str(raw.get()).expect("application producers return valid JSON")
}

fn invalid(operation: &'static str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Offline artifact workflow input is invalid.".into(),
        false,
        "Provide the required bounded report or complete Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

fn unsupported(operation: ArtifactWorkflowOperation, reason: &str) -> Failure {
    Failure::new(
        "unsupported_request",
        "unsupported_request",
        reason.into(),
        false,
        "Use the existing artifact-owning adapter for this operation.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Offline artifact workflow operation is unknown: {name}"),
        false,
        "Select a supported offline artifact workflow.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
