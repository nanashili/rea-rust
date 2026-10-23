//! Captured-Evidence-only adapter for `inspect_managed_members`.
//!
//! The managed artifact reader owns PE/CLI decoding and member interpretation.
//! This adapter authenticates a retained record and returns its normalized
//! report without reopening the artifact or remapping build-local identities.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_managed_members";

/// Project one complete retained managed-members Evidence record.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    if request.len() != 1 || !request.contains_key("evidence") {
        return Err(invalid("input must contain exactly the evidence field"));
    }

    let evidence = request
        .get("evidence")
        .ok_or_else(|| invalid("evidence is required"))?;
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("evidence could not be encoded: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "evidence operation must be inspect_managed_members",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("managed members result is invalid JSON: {error}")))?;
    if !result.is_object() {
        return Err(invalid("managed members result must be an object"));
    }
    let result_object = result
        .as_object()
        .expect("managed members result was checked to be an object");
    let path = result_object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("managed members result must retain artifact path"))?;
    if path.is_empty() || path.contains('\0') {
        return Err(invalid("managed members result must retain artifact path"));
    }
    let digest = result_object
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("managed members result must retain artifact SHA-256"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid("managed members artifact SHA-256 is invalid"));
    }
    let members = result_object
        .get("members")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("managed members result must retain member facts"))?;

    for collection in [
        "references",
        "module_references",
        "exported_types",
        "types",
        "fields",
        "methods",
        "params",
        "properties",
        "events",
        "generic_params",
        "generic_constraints",
        "method_specs",
        "member_references",
        "call_edges",
        "field_accesses",
    ] {
        if !members.get(collection).is_some_and(Value::is_array) {
            return Err(invalid("managed members collection must be an array"));
        }
    }

    let selection = members
        .get("selection")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("managed members selection is missing"))?;
    if !selection
        .get("type_names")
        .is_some_and(|value| value.is_null() || value.is_array())
        || !selection
            .get("unmatched_type_names")
            .is_some_and(Value::is_array)
    {
        return Err(invalid("managed members selection is invalid"));
    }

    if !result_object
        .keys()
        .all(|key| matches!(key.as_str(), "path" | "sha256" | "members"))
    {
        return Err(invalid("managed members result contains unknown fields"));
    }

    if !members.keys().all(|key| {
        matches!(
            key.as_str(),
            "module"
                | "assembly"
                | "references"
                | "module_references"
                | "exported_types"
                | "types"
                | "fields"
                | "methods"
                | "params"
                | "properties"
                | "events"
                | "generic_params"
                | "generic_constraints"
                | "method_specs"
                | "member_references"
                | "call_edges"
                | "field_accesses"
                | "selection"
        )
    }) {
        return Err(invalid("managed members contains unknown fields"));
    }
    Ok(result)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Managed members Evidence input is invalid.".into(),
        false,
        "Provide retained inspect_managed_members Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
            (
                "authority",
                Detail::Text("offline_capture_only".into()),
            ),
        ]),
    )
}
