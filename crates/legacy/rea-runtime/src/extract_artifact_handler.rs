//! Runtime boundary for the public `extract_artifact` operation.
//!
//! The artifact extraction producer owns validation, digest binding, path
//! selection, and deterministic result construction.  This module owns only
//! operation dispatch.  It does not acquire a target, create an output tree,
//! or delete caller files; those capabilities remain with the stateful
//! artifact provider that supplies the retained inventory and observed bytes.

use rea_application::artifacts;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = "extract_artifact";

/// The one operation owned by this runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtractArtifactOperation {
    Extract,
}

impl ExtractArtifactOperation {
    /// Parse the exact public operation name and reject every other operation.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        if name == OPERATION {
            Ok(Self::Extract)
        } else {
            Err(unknown_operation(name))
        }
    }

    /// Return the canonical operation name used by transport and Evidence.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Extract => OPERATION,
        }
    }
}

/// Dispatch a retained extraction request through the application producer.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = ExtractArtifactOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed extraction operation.
pub fn dispatch_typed(
    operation: ExtractArtifactOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        ExtractArtifactOperation::Extract => artifacts::extraction::inspect(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Artifact extraction operation is unknown: {name}"),
        false,
        "Select extract_artifact and provide its retained extraction facts.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
