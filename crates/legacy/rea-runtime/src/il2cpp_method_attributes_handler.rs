//! Captured/static boundary for `inspect_il2cpp_method_attributes`.
//!
//! The caller supplies already-parsed IL2CPP method rows. This adapter only
//! delegates bit-field projection and never acquires a provider, opens an
//! artifact, executes target code, or mutates a target.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// The exact public operation exposed by this captured/static adapter.
pub const OPERATION: &str = il2cpp::method_attributes::OPERATION;

/// Decode caller-supplied IL2CPP method and implementation attributes.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without acquiring a target or provider.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    let result = il2cpp::method_attributes::project(input).map_err(tag_failure)?;
    project_public_result(result).map_err(tag_failure)
}

fn project_public_result(mut result: Value) -> Result<Value, Failure> {
    let object = result.as_object_mut().ok_or_else(invalid_projection)?;
    let items = object
        .get_mut("items")
        .and_then(Value::as_array_mut)
        .ok_or_else(invalid_projection)?;

    for item in items {
        strip_application_extensions(item)?;
    }

    // The application projection retains its version and flag projections for
    // native consumers. The runtime contract exposes the stable public fields
    // only, while each original row remains intact as provenance.
    object.remove("metadata_version");
    object.insert("operation".into(), Value::String(OPERATION.into()));

    Ok(result)
}

fn strip_application_extensions(item: &mut Value) -> Result<(), Failure> {
    let item = item.as_object_mut().ok_or_else(invalid_projection)?;
    for field in ["method_attributes", "method_impl_attributes"] {
        item.get_mut(field)
            .and_then(Value::as_object_mut)
            .ok_or_else(invalid_projection)?
            .remove("flag_projection");
    }

    Ok(())
}

fn invalid_projection() -> Failure {
    Failure::new(
        "internal_error",
        "invalid_output",
        "IL2CPP method attributes produced an invalid public result.".into(),
        false,
        "Retry the captured method attributes inspection; report the runtime projection failure if it persists.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("authority".into(), Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
