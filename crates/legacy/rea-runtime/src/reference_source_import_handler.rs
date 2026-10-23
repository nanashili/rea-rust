//! Runtime adapter for historical reference-source imports.
//!
//! The application owner performs the read-only traversal and builds the
//! relocation-independent graph. This boundary only exposes the stable
//! operation name and preserves the operation authority on failures.

use rea_application::reconstruction::reference_source_import;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = reference_source_import::OPERATION;

/// Import a caller-selected source tree as historical reference data.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected import request without provider access.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    reference_source_import::import(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("historical-reference".into()));
    failure
}
