//! Runtime adapter for `inspect_il2cpp_codegen_module_capture`.
//!
//! The application producer owns validation and decoding of the explicit,
//! bounded byte capture. This boundary does not open a file, contact a
//! provider, select a target, or translate the producer's tagged failures.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::codegen_module_capture::OPERATION;

/// Inspect caller-supplied IL2CPP `CodeGenModule` bytes.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    il2cpp::codegen_module_capture::inspect(input).map_err(tag_failure)
}

/// Handle one caller-supplied request without acquiring external resources.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    inspect(input)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
