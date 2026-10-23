//! Captured/static boundary for `map_il2cpp_field_layouts`.
//!
//! Metadata and native layout producers own decoding and normalization. This
//! adapter only forwards caller-supplied rows to the application projection;
//! it does not read artifacts, contact a provider, select a target, or infer
//! unavailable offsets.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::field_layout_map::OPERATION;

/// Project caller-supplied IL2CPP field metadata and layout rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::field_layout_map::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
