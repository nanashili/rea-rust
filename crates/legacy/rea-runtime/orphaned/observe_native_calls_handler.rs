//! Captured-Evidence runtime boundary for `observe_native_calls`.
//!
//! Native call observation is provider-owned.  This handler deliberately
//! accepts only an authenticated retained Evidence record and delegates all
//! shape checks and preservation to the application projection.  It has no
//! LLDB, process, instrumentation, or network authority.

use rea_application::native;
use rea_core::failure::Failure;
use serde_json::Value;

pub const OPERATION: &str = native::call_observation_projection::OPERATION;

/// Project captured native call Evidence under the exact public operation.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    native::call_observation_projection::project(&input)
}

/// Dispatch an already-selected operation without introducing live authority.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    native::call_observation_projection::project(input)
}
