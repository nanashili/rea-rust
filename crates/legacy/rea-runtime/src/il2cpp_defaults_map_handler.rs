//! Static/captured adapter for `map_il2cpp_default_values`.
//!
//! The application projection owns default-data decoding and ownership
//! correlation. This adapter only forwards caller-supplied metadata and bytes;
//! it never opens an artifact, invokes a provider, or attaches to a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::defaults_map::OPERATION;

/// Project caller-supplied captured IL2CPP default values.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring external state.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::defaults_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
