//! Read-only runtime adapter for `inspect_il2cpp_member_metadata`.
//!
//! The application projection owns IL2CPP row decoding and section validation.
//! This boundary forwards caller-supplied captures only; it never reopens an
//! artifact, invokes a provider, or guesses member ownership.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::member_metadata::OPERATION;

/// Project a caller-supplied captured IL2CPP member metadata snapshot.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `inspect_il2cpp_member_metadata` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::member_metadata::project(input).map_err(tag_failure)
}

/// Keep application parsing details while recording this adapter's authority.
/// The projection remains offline and caller-supplied; no malformed or
/// unresolved row is reinterpreted at this boundary.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
