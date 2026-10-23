//! Runtime adapter for explicit IL2CPP `CodeGenModule` layout decoding.
//!
//! The caller supplies the versioned layout descriptor and bounded byte
//! captures.  The application decoder owns all interpretation; this boundary
//! never dereferences pointers, opens an artifact, contacts a provider, or
//! selects a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::codegen_module_layout::OPERATION;

/// Decode a caller-supplied explicit-layout capture.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Decode an already-selected request without acquiring external resources.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let mut result = il2cpp::codegen_module_layout::parse(input).map_err(tag_failure)?;
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
