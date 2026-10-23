//! Typed dispatch for caller-supplied native analysis observations.
//!
//! The provider boundary owns database access, image loading, command
//! execution, and Evidence envelopes. This module only selects an existing
//! application producer for facts already supplied by an adapter. In
//! particular, it never opens an analysis database, executes an artifact, or
//! invokes objdump.

use rea_application::{binary::objdump_inspection, native, native::function_analysis_projection};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Native analysis operations supported by retained, caller-supplied facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeAnalysisOperation {
    AnalyzeFunction,
    BinaryOverview,
    InspectLoadImage,
    InspectDataType,
    InspectInstruction,
    InspectDispatchMetadata,
    InspectApi,
    InspectWithObjdump,
}

impl NativeAnalysisOperation {
    /// Parse the public operation name used by CLI and MCP callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            function_analysis_projection::OPERATION => Ok(Self::AnalyzeFunction),
            native::binary_overview::OPERATION => Ok(Self::BinaryOverview),
            native::load_image::OPERATION => Ok(Self::InspectLoadImage),
            native::data_type::OPERATION => Ok(Self::InspectDataType),
            native::instruction::OPERATION => Ok(Self::InspectInstruction),
            native::dispatch_metadata::OPERATION => Ok(Self::InspectDispatchMetadata),
            native::api_inspection::OPERATION => Ok(Self::InspectApi),
            objdump_inspection::OPERATION => Ok(Self::InspectWithObjdump),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyzeFunction => function_analysis_projection::OPERATION,
            Self::BinaryOverview => native::binary_overview::OPERATION,
            Self::InspectLoadImage => native::load_image::OPERATION,
            Self::InspectDataType => native::data_type::OPERATION,
            Self::InspectInstruction => native::instruction::OPERATION,
            Self::InspectDispatchMetadata => native::dispatch_metadata::OPERATION,
            Self::InspectApi => native::api_inspection::OPERATION,
            Self::InspectWithObjdump => objdump_inspection::OPERATION,
        }
    }
}

/// Dispatch one operation using only the supplied observation or Evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = NativeAnalysisOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without reparsing its name.
pub fn dispatch_typed(operation: NativeAnalysisOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        NativeAnalysisOperation::AnalyzeFunction => function_analysis_projection::normalize(input),
        NativeAnalysisOperation::BinaryOverview => native::binary_overview::project(input),
        NativeAnalysisOperation::InspectLoadImage => native::load_image::inspect(input),
        NativeAnalysisOperation::InspectDataType => native::data_type::inspect(input),
        NativeAnalysisOperation::InspectInstruction => native::instruction::inspect(input),
        NativeAnalysisOperation::InspectDispatchMetadata => {
            native::dispatch_metadata::inspect(input)
        }
        NativeAnalysisOperation::InspectApi => native::api_inspection::inspect(input),
        NativeAnalysisOperation::InspectWithObjdump => objdump_inspection::inspect_value(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Native analysis operation is unknown: {name}"),
        false,
        "Select a caller-supplied native analysis operation supported by the retained-facts handler.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
