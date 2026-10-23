//! Runtime adapter for captured IL2CPP native-image mapping.
//!
//! The caller supplies a bounded image snapshot.  The application projection
//! owns format interpretation and preserves unsupported mappings as explicit
//! results; this boundary never opens paths or contacts a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = "inspect_il2cpp_image";
const MAX_PUBLIC_SEGMENTS: usize = 4096;
const MAX_PUBLIC_EXECUTABLE_RANGES: usize = 4096;
const MAX_PUBLIC_LIMITATIONS: usize = 128;

/// Project one caller-supplied image capture.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected request without acquiring external resources.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let mut result = il2cpp::image_mapping_operation::project(input).map_err(tag_failure)?;
    validate_public_bounds(&result).map_err(tag_failure)?;
    let object = result.as_object_mut().ok_or_else(invalid_projection)?;
    object.insert("operation".into(), Value::String(OPERATION.into()));
    Ok(result)
}

fn validate_public_bounds(result: &Value) -> Result<(), Failure> {
    let object = result.as_object().ok_or_else(invalid_projection)?;

    validate_array_bound(object, "segments", MAX_PUBLIC_SEGMENTS)?;
    validate_array_bound(object, "executable_ranges", MAX_PUBLIC_EXECUTABLE_RANGES)?;
    validate_array_bound(object, "limitations", MAX_PUBLIC_LIMITATIONS)?;

    Ok(())
}

fn validate_array_bound(
    object: &serde_json::Map<String, Value>,
    field: &str,
    maximum: usize,
) -> Result<(), Failure> {
    let Some(value) = object.get(field) else {
        return Err(invalid_projection());
    };
    let Some(values) = value.as_array() else {
        return Err(invalid_projection());
    };
    if values.len() > maximum {
        return Err(Failure::new(
            "invalid_result",
            "invalid_output",
            format!("IL2CPP image projection field '{field}' exceeds its public limit."),
            false,
            "Retry with a capture whose mapped image fits the public result bounds.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("authority", Detail::Text("offline_capture_only".into())),
            ]),
        ));
    }

    Ok(())
}

fn invalid_projection() -> Failure {
    Failure::new(
        "internal_error",
        "invalid_output",
        "IL2CPP image mapping produced a non-object result.".into(),
        false,
        "Retry the captured image inspection; report the runtime projection failure if it persists.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
