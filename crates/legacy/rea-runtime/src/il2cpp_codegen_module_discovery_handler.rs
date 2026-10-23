//! Captured/static boundary for IL2CPP CodeGenModule discovery.
//!
//! The application projection owns byte interpretation and candidate
//! disposition. This adapter only delegates bounded caller-owned captures; it
//! never opens an image, contacts a provider, or selects a candidate.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::codegen_module_discovery_projection::OPERATION;

/// Discover all candidates in a caller-supplied static image capture.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected request without external resource access.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let input = collapse_equivalent_mapping_aliases(input);
    il2cpp::codegen_module_discovery_projection::project(&input).map_err(tag_failure)
}

fn collapse_equivalent_mapping_aliases(input: &Value) -> Value {
    let Some(root) = input.as_object() else {
        return input.clone();
    };
    let (Some(mappings), Some(address_mappings)) =
        (root.get("mappings"), root.get("address_mappings"))
    else {
        return input.clone();
    };
    if mappings != address_mappings {
        return input.clone();
    }

    let mut normalized = root.clone();
    normalized.remove("address_mappings");
    Value::Object(normalized)
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
