//! Runtime adapter for `map_il2cpp_native_xrefs`.
//!
//! The application projection owns digest, address-space, and target-address
//! matching. This adapter forwards caller-supplied captured rows only; it does
//! not disassemble binaries, infer control flow, or execute a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::native_xrefs::OPERATION;

/// Correlate captured native xrefs with IL2CPP method-address rows.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected native-xref mapping request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::native_xrefs::project(input).map_err(tag_failure)
}

/// Keep failures explicit about this operation's captured-only authority.
fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
