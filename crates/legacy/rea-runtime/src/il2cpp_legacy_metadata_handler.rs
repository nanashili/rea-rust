//! Runtime adapter for captured legacy IL2CPP metadata headers.
//!
//! The application projection owns the version-specific header checks and
//! caller-supplied ownership facts. This boundary only forwards a bounded
//! capture and never opens an artifact or contacts a provider.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::legacy_metadata::OPERATION;

/// Project one caller-supplied legacy metadata capture.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected captured-only request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let result = il2cpp::legacy_metadata::project_captured(input).map_err(tag_failure)?;
    project_public_result(result).map_err(tag_failure)
}

/// Keep the runtime result aligned with the stable public contract.
///
/// The application projection retains raw header pairs and detailed coverage
/// facts for native consumers. The public runtime contract exposes the
/// normalized header and section facts, so those application-only extensions
/// are removed here at the adapter boundary.
fn project_public_result(mut result: Value) -> Result<Value, Failure> {
    let object = result.as_object_mut().ok_or_else(invalid_projection)?;
    object.remove("source");

    let coverage = object
        .get_mut("coverage")
        .and_then(Value::as_object_mut)
        .ok_or_else(invalid_projection)?;
    coverage.remove("sections");
    coverage.remove("captured_byte_bounds_validated");

    object.insert("operation".into(), Value::String(OPERATION.into()));
    Ok(result)
}

fn invalid_projection() -> Failure {
    Failure::new(
        "internal_error",
        "invalid_output",
        "Legacy IL2CPP metadata produced an invalid public result.".into(),
        false,
        "Retry the captured legacy metadata inspection; report the runtime projection failure if it persists.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            (
                "authority",
                Detail::Text("offline_capture_only".into()),
            ),
        ]),
    )
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
