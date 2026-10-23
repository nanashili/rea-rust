//! Captured/static boundary for `label_il2cpp_symbols`.
//!
//! Labels are derived only from caller-supplied normalized metadata rows. The
//! adapter does not inspect a binary or claim that a managed label is a native
//! symbol or recovered body.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::symbol_labels::OPERATION;

/// Project caller-supplied IL2CPP metadata rows without live access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_request_shape(input).map_err(tag_failure)?;
    il2cpp::symbol_labels::project(input).map_err(tag_failure)
}

/// Enforce the public envelope before delegating row semantics to the
/// application projection.  The contract admits exactly one of the direct or
/// metadata-wrapped forms and does not permit adapter-only top-level fields.
fn validate_request_shape(input: &Value) -> Result<(), Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("Input must be an object."))?;

    if let Some(metadata) = root.get("metadata") {
        if root.len() != 1 {
            return Err(invalid(
                "Metadata input may contain only the metadata field.",
            ));
        }
        let metadata = metadata
            .as_object()
            .ok_or_else(|| invalid("Metadata input must contain an object."))?;
        require_rows(metadata, "metadata")
    } else {
        require_rows(root, "direct")
    }
}

fn require_rows(object: &serde_json::Map<String, Value>, scope: &str) -> Result<(), Failure> {
    if object.len() != 2 || !object.contains_key("types") || !object.contains_key("methods") {
        return Err(invalid(&format!(
            "{scope} input must contain only types and methods arrays."
        )));
    }

    if !object.get("types").is_some_and(Value::is_array)
        || !object.get("methods").is_some_and(Value::is_array)
    {
        return Err(invalid(&format!(
            "{scope} types and methods must be arrays."
        )));
    }

    Ok(())
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide direct or metadata-wrapped IL2CPP rows and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
