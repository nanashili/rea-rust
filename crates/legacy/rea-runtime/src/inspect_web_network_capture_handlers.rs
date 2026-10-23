//! Runtime adapter for the public `inspect_web_network_capture` operation.
//!
//! The application producer owns capture validation, bounded file reading,
//! format projection, redaction, and result provenance. This adapter only
//! selects the named operation and delegates the caller's request unchanged.

use rea_application::web;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The historical capture operation exposed by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    InspectWebNetworkCapture,
}

impl Operation {
    /// Parse the canonical public operation name and reject every other name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            web::network_capture::OPERATION => Ok(Self::InspectWebNetworkCapture),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the operation name used by contracts and producer diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectWebNetworkCapture => web::network_capture::OPERATION,
        }
    }
}

/// Inspect one caller-selected retained capture through the application
/// producer. The producer result is returned unchanged to preserve its exact
/// capture shape and Evidence-relevant provenance fields.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = Operation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed operation without reinterpreting its input.
pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::InspectWebNetworkCapture => web::network_capture::inspect(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Web network capture operation is unknown: {name}"),
        false,
        "Select inspect_web_network_capture for bounded offline capture inspection.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
