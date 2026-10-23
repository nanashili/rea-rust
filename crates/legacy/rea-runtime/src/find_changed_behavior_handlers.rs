//! Isolated runtime adapter for `find_changed_behavior`.
//!
//! Comparison Evidence is produced and authenticated upstream.  This module
//! only binds the stable operation name to the shared application projection;
//! it does not reinterpret Evidence, discard provenance, or register the
//! operation with the production MCP router.

use rea_application::investigation::changed_behavior;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Operation names understood by this isolated runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FindChangedBehaviorOperation {
    FindChangedBehavior,
}

impl FindChangedBehaviorOperation {
    /// Parse the canonical public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            changed_behavior::OPERATION => Ok(Self::FindChangedBehavior),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::FindChangedBehavior => changed_behavior::OPERATION,
        }
    }
}

/// Dispatch one retained-Evidence changed-behavior projection.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = FindChangedBehaviorOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed operation without changing the caller input.
pub fn dispatch_typed(
    operation: FindChangedBehaviorOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        FindChangedBehaviorOperation::FindChangedBehavior => changed_behavior::compare(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Changed-behavior operation is unknown: {name}"),
        false,
        "Select the supported changed-behavior operation.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
