//! Isolated runtime dispatch for static/runtime correlation.
//!
//! The application layer owns Evidence validation and correlation semantics.
//! This adapter only exposes the public operation name and delegates the
//! caller-supplied request without acquiring target, process, or provider
//! authority.

use rea_application::investigation::static_runtime_correlation;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Public operation handled by this isolated runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticRuntimeOperation {
    Correlate,
}

impl StaticRuntimeOperation {
    /// Parse the stable public operation name used by MCP and CLI callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            static_runtime_correlation::OPERATION => Ok(Self::Correlate),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Correlate => static_runtime_correlation::OPERATION,
        }
    }
}

/// Dispatch one caller-supplied static/runtime correlation request.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = StaticRuntimeOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without reparsing its name.
pub fn dispatch_typed(operation: StaticRuntimeOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        StaticRuntimeOperation::Correlate => static_runtime_correlation::correlate(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Static/runtime operation is unknown: {name}"),
        false,
        "Select correlate_static_and_runtime and provide explicit comparison Evidence mappings."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
