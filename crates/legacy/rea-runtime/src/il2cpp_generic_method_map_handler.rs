//! Runtime adapter for `map_il2cpp_generic_methods`.
//!
//! The metadata and binary producers own decoding and normalization. This
//! boundary only forwards caller-supplied facts to the application projection;
//! it does not read files, contact a provider, select a target, or reinterpret
//! unknown and ambiguous mappings.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::generic_method_map::OPERATION;

/// Project normalized IL2CPP metadata and binary facts.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `map_il2cpp_generic_methods` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::generic_method_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
