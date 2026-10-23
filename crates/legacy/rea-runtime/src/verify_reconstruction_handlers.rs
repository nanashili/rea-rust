//! Isolated runtime adapter for `verify_reconstruction`.
//!
//! The session owns Evidence authentication and retention. This adapter only
//! separates the caller's finite specification from the already retained
//! bundle and delegates evaluation to the application module. It does not
//! select records, resolve unknowns, or infer coverage locally.

use rea_application::reconstruction;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable operation supported by this isolated adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    VerifyReconstruction,
}

impl Operation {
    /// Parse the public operation name.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            reconstruction::verification::OPERATION => Ok(Self::VerifyReconstruction),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::VerifyReconstruction => reconstruction::verification::OPERATION,
        }
    }
}

/// Dispatch verification using a caller-selected specification and retained
/// complete Evidence bundle.
pub fn dispatch(operation: &str, input: Value, bundle: Value) -> Result<Value, Failure> {
    dispatch_typed(Operation::parse(operation)?, &input, &bundle)
}

/// Dispatch an already parsed operation without contacting a provider.
pub fn dispatch_typed(
    operation: Operation,
    input: &Value,
    bundle: &Value,
) -> Result<Value, Failure> {
    match operation {
        Operation::VerifyReconstruction => reconstruction::verification::project(input, bundle),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Reconstruction verification operation is unknown: {name}"),
        false,
        "Select verify_reconstruction and provide a finite specification.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
