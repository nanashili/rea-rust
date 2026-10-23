//! Captured/static boundary for `scan_il2cpp_registration_candidates`.
//!
//! Registration candidates are supplied by the caller or retained Evidence.
//! The application projection owns their strict schema and interpretation;
//! this adapter does not read an artifact, attach to a process, or select a
//! provider.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = "scan_il2cpp_registration_candidates";

/// Project caller-supplied registration candidates without live authority.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::registration_scan_projection::project(input).map_err(tag_failure)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
