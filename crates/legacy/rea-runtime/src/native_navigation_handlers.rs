//! Dispatch for captured native navigation and address-context observations.
//!
//! The provider adapter owns cursor access, document selection, and address
//! spelling. This module only projects retained observations into the shared
//! application shapes, so it never moves a native UI cursor or consults a
//! live provider.

use rea_application::{native, native::address_file_offset, native::navigation_context};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Read-only native operations represented by this captured handler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeNavigationOperation {
    GetNavigationContext,
    InspectAddressContext,
    AddressName,
    CurrentAddress,
    CurrentProcedure,
    CurrentDocument,
    NextAddress,
    PrevAddress,
    AddressToFileOffset,
    InspectNativeAnnotation,
}

impl NativeNavigationOperation {
    /// Parse the public operation name used by MCP and CLI adapters.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "get_navigation_context" => Ok(Self::GetNavigationContext),
            "inspect_address_context" => Ok(Self::InspectAddressContext),
            "address_name" => Ok(Self::AddressName),
            "current_address" => Ok(Self::CurrentAddress),
            "current_procedure" => Ok(Self::CurrentProcedure),
            "current_document" => Ok(Self::CurrentDocument),
            "next_address" => Ok(Self::NextAddress),
            "prev_address" => Ok(Self::PrevAddress),
            "address_to_file_offset" => Ok(Self::AddressToFileOffset),
            "inspect_native_annotation" => Ok(Self::InspectNativeAnnotation),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::GetNavigationContext => "get_navigation_context",
            Self::InspectAddressContext => "inspect_address_context",
            Self::AddressName => "address_name",
            Self::CurrentAddress => "current_address",
            Self::CurrentProcedure => "current_procedure",
            Self::CurrentDocument => "current_document",
            Self::NextAddress => "next_address",
            Self::PrevAddress => "prev_address",
            Self::AddressToFileOffset => "address_to_file_offset",
            Self::InspectNativeAnnotation => "inspect_native_annotation",
        }
    }
}

/// Dispatch one captured native navigation operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = NativeNavigationOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an operation whose public name has already been parsed.
pub fn dispatch_typed(
    operation: NativeNavigationOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        NativeNavigationOperation::GetNavigationContext => navigation_context::project_value(input),
        NativeNavigationOperation::InspectAddressContext => native::address_context::inspect(input),
        NativeNavigationOperation::AddressToFileOffset => address_file_offset::project(input),
        NativeNavigationOperation::AddressName => project_annotation(input, "address_name"),
        NativeNavigationOperation::InspectNativeAnnotation => {
            native::annotation_inspection::inspect(input)
        }
        NativeNavigationOperation::CurrentAddress
        | NativeNavigationOperation::CurrentProcedure
        | NativeNavigationOperation::CurrentDocument
        | NativeNavigationOperation::NextAddress
        | NativeNavigationOperation::PrevAddress => project_text(input, operation.name()),
    }
}

fn project_annotation(input: &Value, operation: &str) -> Result<Value, Failure> {
    if input.get("evidence").is_some()
        || input.get("native_observation").is_some()
        || input.get("annotation").is_some()
    {
        return native::annotation_inspection::project(input);
    }

    let value = retained_value(input, operation)?;
    if value.is_null() || value.is_string() {
        return Ok(value);
    }

    Err(invalid(
        operation,
        "annotation result must be a string or null",
    ))
}

fn project_text(input: &Value, operation: &str) -> Result<Value, Failure> {
    let value = retained_value(input, operation)?;
    if value.as_str().is_some_and(|text| !text.is_empty()) {
        return Ok(value);
    }

    Err(invalid(operation, "result must be a non-empty string"))
}

fn retained_value(input: &Value, operation: &str) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "captured operation input must be an object"))?;

    for key in ["normalized_result", "result", "value"] {
        if let Some(value) = object.get(key) {
            return Ok(value.clone());
        }
    }

    if let Some(evidence) = object.get("evidence") {
        for key in ["normalized_result", "result", "value"] {
            if let Some(value) = evidence.get(key) {
                return Ok(value.clone());
            }
        }
    }

    Err(invalid(operation, "captured operation result is required"))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Native navigation operation is unknown: {name}"),
        false,
        "Select one of the supported captured native navigation operations.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a retained native observation and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            (
                "input_shape",
                Detail::Text("captured native observation".into()),
            ),
        ]),
    )
}
