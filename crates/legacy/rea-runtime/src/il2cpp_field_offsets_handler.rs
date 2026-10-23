//! Static/captured adapter for `decode_il2cpp_field_offsets`.
//!
//! The application projection owns the explicit layout and bounded decoding
//! rules. This adapter does not read an artifact, attach to a process, or
//! infer pointer width, byte order, offset encoding, or sentinel meaning.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::field_offsets_decode::OPERATION;

/// Decode caller-supplied captured IL2CPP field-offset bytes.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::field_offsets_decode::project(input).map_err(tag_failure)
}

/// Keep failures explicit about the captured-only runtime boundary while
/// retaining the application owner's field and reason details.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
