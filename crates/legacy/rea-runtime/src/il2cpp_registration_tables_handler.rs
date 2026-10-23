//! Captured/static boundary for `project_il2cpp_registration_tables`.
//!
//! Registration-table facts are supplied by the caller.  The application
//! projection owns the versioned layout and candidate validation; this
//! adapter only preserves the operation boundary and failure provenance.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Exact public operation exposed by this captured/static adapter.
///
/// Keep the runtime route name owned by this boundary. The application
/// projection remains an implementation dependency and must not redefine the
/// public contract name.
pub const OPERATION: &str = "project_il2cpp_registration_tables";

/// Project caller-supplied registration-table observations.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch without opening an artifact, contacting a provider, or acquiring
/// target authority.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let mut result = il2cpp::registration_tables::project(input).map_err(tag_failure)?;

    if let Some(object) = result.as_object_mut() {
        object.insert("operation".into(), Value::String(OPERATION.into()));
    }

    Ok(result)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
