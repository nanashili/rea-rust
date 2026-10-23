//! Typed dispatch for captured JEB application observations.
//!
//! The JEB transport owns endpoint communication, project state, and engine
//! lifecycle. This layer only selects the corresponding application producer
//! for a captured request and preserves that producer's exact result or
//! tagged failure. It is intentionally usable by both MCP and CLI adapters.

use rea_application::{
    jeb,
    };
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// JEB operations whose captured results can be projected by this runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JebOperation {
    InspectClient,
    OpenProject,
    ListUnits,
    DecompileItem,
}

impl JebOperation {
    /// Parse the public operation name used by MCP and CLI callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            jeb::client::OPERATION => Ok(Self::InspectClient),
            jeb::project::OPERATION => Ok(Self::OpenProject),
            jeb::units::OPERATION => Ok(Self::ListUnits),
            jeb::decompile_projection::OPERATION => Ok(Self::DecompileItem),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical operation name for this handler.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectClient => jeb::client::OPERATION,
            Self::OpenProject => jeb::project::OPERATION,
            Self::ListUnits => jeb::units::OPERATION,
            Self::DecompileItem => jeb::decompile_projection::OPERATION,
        }
    }
}

/// Dispatch one captured JEB operation by its public operation name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = JebOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch one captured JEB operation after its name has been parsed.
pub fn dispatch_typed(operation: JebOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        JebOperation::InspectClient => jeb::client::inspect_value(input),
        JebOperation::OpenProject => jeb::project::inspect_value(input),
        JebOperation::ListUnits => project_captured_result(
            input,
            jeb::units::normalize_value,
            jeb::units::OPERATION,
        ),
        JebOperation::DecompileItem => jeb::decompile_projection::decompile_jeb_item(input),
    }
}

/// Project a captured provider result while accepting the standard Evidence
/// envelope used by the runtime adapters. Direct normalized values remain
/// valid, which keeps this boundary useful for CLI callers that have already
/// unwrapped their capture.
fn project_captured_result(
    input: &Value,
    project: fn(&Value) -> Result<Value, Failure>,
    operation: &str,
) -> Result<Value, Failure> {
    let result = captured_result(input, operation)?;
    project(result)
}

fn captured_result<'a>(input: &'a Value, operation: &str) -> Result<&'a Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "captured JEB operation input must be an object"))?;

    if object.get("engine").is_some() {
        return Ok(input);
    }

    if let Some(evidence) = object.get("evidence") {
        return captured_evidence_result(evidence, operation);
    }

    for key in ["normalized_result", "result", "value"] {
        if let Some(result) = object.get(key) {
            return Ok(result);
        }
    }

    Err(invalid(
        operation,
        "captured JEB operation result or Evidence is required",
    ))
}

fn captured_evidence_result<'a>(
    evidence: &'a Value,
    operation: &str,
) -> Result<&'a Value, Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid(operation, "JEB Evidence must be an object"))?;

    if let Some(evidence_operation) = object.get("operation")
        && evidence_operation.as_str() != Some(operation)
    {
        return Err(invalid(operation, "JEB Evidence has the wrong operation"));
    }

    for key in ["normalized_result", "result", "value"] {
        if let Some(result) = object.get(key) {
            return Ok(result);
        }
    }

    Err(invalid(operation, "JEB Evidence is missing its result"))
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide caller-supplied captured JEB output or Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("JEB operation is unknown: {name}"),
        false,
        "Select one of the supported captured JEB operations.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
