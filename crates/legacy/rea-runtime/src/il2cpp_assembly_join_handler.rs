//! Runtime adapter for `join_il2cpp_assemblies`.
//!
//! The application projection owns identity extraction and matching.  This
//! adapter only forwards caller-supplied metadata and CodeGenModule facts;
//! it never opens artifacts or fills in an unresolved identity.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::assembly_join::OPERATION;

/// Project captured metadata images and CodeGenModule identities.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected `join_il2cpp_assemblies` request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::assembly_join::project(input).map_err(tag_failure)
}

/// Keep the public failure contract explicit about this adapter's authority.
/// The application projection reports the precise input field and reason;
/// this boundary adds the fact that no live artifact or provider was involved.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
