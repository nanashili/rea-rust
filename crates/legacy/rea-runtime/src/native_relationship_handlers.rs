//! Runtime dispatch for retained native relationship observations.
//!
//! Provider adapters own address resolution, instruction decoding, name
//! lookup, and relationship discovery. This module deliberately has no
//! provider or host dependency: it only selects the matching application
//! projection for caller-supplied observations that were already retained as
//! Evidence. Missing observations remain the application's explicit unknown
//! or unavailable result.

use rea_application::{native, native::build_call_path, native::trace_call_path};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Native relationship workflows supported by retained observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeRelationshipOperation {
    GetCallGraph,
    TraceCallPath,
    TraceFeature,
    TraceNativeValues,
    BuildCallPath,
    FindXrefsToName,
    ResolveNativeCallTargets,
}

impl NativeRelationshipOperation {
    /// Parse the stable operation name used by CLI and MCP callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            native::call_graph::OPERATION => Ok(Self::GetCallGraph),
            trace_call_path::OPERATION => Ok(Self::TraceCallPath),
            native::trace_feature::OPERATION => Ok(Self::TraceFeature),
            native::trace_values::OPERATION => Ok(Self::TraceNativeValues),
            build_call_path::OPERATION => Ok(Self::BuildCallPath),
            native::xrefs::OPERATION => Ok(Self::FindXrefsToName),
            native::call_targets::OPERATION => Ok(Self::ResolveNativeCallTargets),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::GetCallGraph => native::call_graph::OPERATION,
            Self::TraceCallPath => trace_call_path::OPERATION,
            Self::TraceFeature => native::trace_feature::OPERATION,
            Self::TraceNativeValues => native::trace_values::OPERATION,
            Self::BuildCallPath => build_call_path::OPERATION,
            Self::FindXrefsToName => native::xrefs::OPERATION,
            Self::ResolveNativeCallTargets => native::call_targets::OPERATION,
        }
    }
}

/// Dispatch a retained native relationship request by its public name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = NativeRelationshipOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch a request after its operation name has been parsed by the caller.
pub fn dispatch_typed(
    operation: NativeRelationshipOperation,
    input: &Value,
) -> Result<Value, Failure> {
    validate_public_input(operation, input)?;

    match operation {
        NativeRelationshipOperation::GetCallGraph => native::call_graph::project(input),
        NativeRelationshipOperation::TraceCallPath => trace_call_path::trace(input),
        NativeRelationshipOperation::TraceFeature => native::trace_feature::trace(input),
        NativeRelationshipOperation::TraceNativeValues => native::trace_values::trace(input),
        NativeRelationshipOperation::BuildCallPath => build_call_path::build(input),
        NativeRelationshipOperation::FindXrefsToName => native::xrefs::find(input),
        NativeRelationshipOperation::ResolveNativeCallTargets => {
            native::call_targets::resolve(input)
        }
    }
}

fn validate_public_input(
    operation: NativeRelationshipOperation,
    input: &Value,
) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input(operation, "input must be an object"))?;

    let allowed = match operation {
        NativeRelationshipOperation::GetCallGraph => &["address", "direction", "functions"][..],
        NativeRelationshipOperation::TraceCallPath => {
            &["start", "goal", "direction", "observations"][..]
        }
        NativeRelationshipOperation::BuildCallPath => &["functions", "start", "goal"][..],
        _ => return Ok(()),
    };

    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid_input(
            operation,
            &format!("unknown input field: {field}"),
        ));
    }

    Ok(())
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Native relationship operation is unknown: {name}"),
        false,
        "Select a supported native relationship workflow and provide its retained observations."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}

fn invalid_input(operation: NativeRelationshipOperation, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the canonical retained relationship input and retry.".into(),
        BTreeMap::from([(
            String::from("operation"),
            Detail::Text(operation.name().into()),
        )]),
    )
}
