//! Runtime adapter for `project_il2cpp_string_literals`.
//!
//! The metadata reader owns binary layout decoding. This adapter forwards
//! caller-supplied literal rows and data bytes to the application projection;
//! it does not read artifacts, execute a target, or resolve unknown strings.

use rea_application::il2cpp;
use rea_core::failure::Failure;
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::string_literals::OPERATION;

/// Project caller-supplied IL2CPP string-literal rows and data bytes.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected static or captured request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    il2cpp::string_literals::project(input)
}
