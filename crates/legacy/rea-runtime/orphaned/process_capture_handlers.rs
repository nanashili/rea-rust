//! Runtime boundary for retained process-capture comparison Evidence.
//!
//! The application layer owns comparison semantics. This adapter only binds
//! the stable public operation name to that implementation. It never captures
//! a process, performs cleanup, opens a provider, or mutates Evidence.

use rea_application::process;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Public process-capture operations understood by this isolated adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessCaptureOperation {
    CompareCaptures,
}

impl ProcessCaptureOperation {
    /// Parse the canonical public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            process::capture_comparison::OPERATION => Ok(Self::CompareCaptures),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CompareCaptures => process::capture_comparison::OPERATION,
        }
    }
}

/// Dispatch one retained-Evidence process comparison.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = ProcessCaptureOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed process comparison operation.
pub fn dispatch_typed(
    operation: ProcessCaptureOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        ProcessCaptureOperation::CompareCaptures => process::capture_comparison::compare(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Process-capture operation is unknown: {name}"),
        false,
        "Select compare_process_captures and provide two process-capture Evidence records.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
