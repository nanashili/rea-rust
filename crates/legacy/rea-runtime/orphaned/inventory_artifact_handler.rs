//! Isolated runtime handler for the retained `inventory_artifact` projection.
//!
//! The inventory producer remains responsible for reading the target and
//! constructing graph facts.  This handler only validates caller identity,
//! normalizes the retained producer report, and binds the report to the
//! selected artifact digest.

use rea_application::artifacts;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inventory_artifact";

/// Normalize one retained artifact inventory without contacting a provider.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = input
        .as_object()
        .ok_or_else(|| invalid("request must be an object"))?;
    let path = required_text(request, "path")?;
    let selected_sha256 = required_sha256(request.get("sha256"))?;
    let integrity_policy = required_policy(request.get("integrity_policy"))?;
    let inventory_input = request
        .get("inventory")
        .cloned()
        .ok_or_else(|| invalid("inventory is required"))?;
    let mut inventory = artifacts::inventory_evidence::normalize_result(inventory_input)
        .map_err(|reason| invalid(&reason))?;
    validate_root_digest(&inventory, selected_sha256)?;
    append_provenance(&mut inventory, path, integrity_policy);
    Ok(inventory)
}

fn validate_root_digest(inventory: &Value, selected_sha256: &str) -> Result<(), Failure> {
    let observed = inventory
        .pointer("/manifest/root_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("inventory manifest has no root_sha256"))?;
    if observed == selected_sha256 {
        return Ok(());
    }
    Err(Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "Selected artifact digest does not match the inventory root digest.".into(),
        false,
        "Select the inventory produced for the caller-selected artifact and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("selected_sha256", Detail::Text(selected_sha256.into())),
            ("inventory_sha256", Detail::Text(observed.into())),
        ]),
    ))
}

fn append_provenance(inventory: &mut Value, path: &str, integrity_policy: &str) {
    let Some(object) = inventory.as_object_mut() else { return; };
    let provenance = object
        .entry("provenance")
        .or_insert_with(|| Value::Array(Vec::new()));
    let Some(values) = provenance.as_array_mut() else { return; };
    values.push(serde_json::json!({
        "tool": OPERATION,
        "arguments": [path],
        "effects": ["projected caller-selected artifact inventory"],
        "integrity_policy": integrity_policy,
    }));
}

fn required_text<'a>(request: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    request
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string without NUL bytes")))
}

fn required_sha256<'a>(value: Option<&'a Value>) -> Result<&'a str, Failure> {
    let digest = value
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        .ok_or_else(|| invalid("sha256 must be a lowercase SHA-256 digest"))?;
    Ok(digest)
}

fn required_policy<'a>(value: Option<&'a Value>) -> Result<&'a str, Failure> {
    let policy = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("integrity_policy is required"))?;
    match policy {
        "fail" | "record-and-continue" => Ok(policy),
        _ => Err(invalid("integrity_policy must be fail or record-and-continue")),
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Artifact inventory input is invalid.".into(),
        false,
        "Provide the selected artifact path, digest, integrity policy, and inventory report.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
