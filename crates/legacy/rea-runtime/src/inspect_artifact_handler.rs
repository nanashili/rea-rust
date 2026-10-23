//! Isolated runtime adapter for the public `inspect_artifact` operation.
//!
//! Artifact inventory owns byte interpretation and graph construction.  This
//! adapter only admits the caller-selected target identity, asks the shared
//! inventory projection to normalize the producer result, and assembles the
//! public inspection envelope.  It does not reopen the target or reinterpret
//! inventory records.

use rea_application::artifacts;
use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = "inspect_artifact";

/// Project one caller-selected artifact and an existing inventory producer
/// result into the public inspection shape.
///
/// The request is intentionally explicit about `path` and `sha256`: those
/// values belong to the selected caller target and must not be inferred from
/// a logical inventory path or replaced by a normalized display value.
pub fn handle(input: &Value) -> Result<Value, Failure> {
    let request = request_object(input)?;
    let path = required_text(request, "path")?;
    let sha256 = required_sha256(request, "sha256")?;
    let integrity_policy = required_integrity_policy(request)?;
    let inventory_input = request
        .get("inventory")
        .cloned()
        .ok_or_else(|| invalid("inventory is required"))?;

    let inventory = artifacts::inventory_evidence::normalize_result(inventory_input)
        .map_err(|reason| invalid(&reason))?;
    validate_root_digest(&inventory, sha256)?;

    let provenance = append_projection_provenance(&inventory, path, integrity_policy);
    let semantic = json!({
        "subject": {
            "path": path,
            "sha256": sha256,
            "root_format": inventory["manifest"]["root_format"],
        },
        "inventory": inventory,
        "provenance": provenance,
        "integrity_policy": integrity_policy,
    });
    let inspection_id = format!(
        "ai_{}",
        canonical_json::digest(&semantic).map_err(|error| invalid(&error.to_string()))?
    );

    Ok(json!({
        "inspection_id": inspection_id,
        "subject": semantic["subject"],
        "inventory": semantic["inventory"],
        "provenance": semantic["provenance"],
        "coverage": semantic["inventory"]["coverage"],
        "limitations": semantic["inventory"]["limitations"],
    }))
}

fn request_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("request must be an object"))
}

fn required_text<'a>(request: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    request
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or_else(|| {
            invalid(&format!(
                "{field} must be a non-empty string without NUL bytes"
            ))
        })
}

fn required_sha256<'a>(request: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    let value = required_text(request, field)?;
    let is_lowercase_sha256 = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if !is_lowercase_sha256 {
        return Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(value)
}

fn required_integrity_policy(request: &Map<String, Value>) -> Result<&str, Failure> {
    let policy = request
        .get("integrity_policy")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("integrity_policy is required"))?;
    match policy {
        "fail" | "record-and-continue" => Ok(policy),
        _ => Err(invalid(
            "integrity_policy must be fail or record-and-continue",
        )),
    }
}

fn validate_root_digest(inventory: &Value, selected_sha256: &str) -> Result<(), Failure> {
    let observed = inventory
        .pointer("/manifest/root_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("inventory manifest has no root_sha256"))?;
    if observed != selected_sha256 {
        return Err(Failure::new(
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
        ));
    }
    Ok(())
}

fn append_projection_provenance(
    inventory: &Value,
    path: &str,
    integrity_policy: &str,
) -> Vec<Value> {
    let mut provenance = inventory
        .get("provenance")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    provenance.push(json!({
        "tool": OPERATION,
        "arguments": [path],
        "effects": ["projected caller-selected artifact inventory"],
        "integrity_policy": integrity_policy,
    }));
    provenance
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Artifact inspection input is invalid.".into(),
        false,
        "Provide the selected artifact path, digest, integrity policy, and inventory producer result."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
