//! Isolated runtime adapter for `evaluate_reconstruction_coverage`.
//!
//! The caller supplies the complete coverage snapshot, verifier observations,
//! capture facts, and authenticated Evidence bundle. The application module
//! owns validation and closure semantics; this adapter does not access
//! providers, targets, files, or external services.

use rea_application::reconstruction;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The operation exposed by this adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    EvaluateReconstructionCoverage,
}

impl Operation {
    /// Parse the stable public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            reconstruction::coverage::OPERATION => Ok(Self::EvaluateReconstructionCoverage),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::EvaluateReconstructionCoverage => reconstruction::coverage::OPERATION,
        }
    }
}

/// Evaluate one caller-supplied, authenticated coverage snapshot.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = Operation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Evaluate an already-selected operation without external access.
pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::EvaluateReconstructionCoverage => reconstruction::coverage::evaluate(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Reconstruction coverage operation is unknown: {name}"),
        false,
        "Select evaluate_reconstruction_coverage and provide captured Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
