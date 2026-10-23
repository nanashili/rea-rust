//! Exact-name application handler for captured binary-layout Evidence.
//!
//! The existing binary-layout adapter owns ELF acquisition and decoding. This
//! handler only selects already retained Evidence and delegates the result
//! shape to that adapter's contract. It never reads a path or reparses bytes,
//! and it keeps artifact identity and provider provenance intact.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = crate::binary::layout::OPERATION;

const MAX_RESULT_BYTES: usize = 64 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024;

/// Validate a caller-selected binary-layout Evidence envelope.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let evidence = selected_evidence(input)?;
    validate_evidence(evidence)
}

/// Return the adapter's captured result without reinterpreting its layout.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    Ok(selected_result(selected_evidence(input)?)?.clone())
}

/// Alias used by application callers that name this step a projection.
pub fn project(input: &Value) -> Result<Value, Failure> {
    inspect(input)
}

fn selected_evidence(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_binary_layout input must be an object"))?;
    object
        .get("evidence")
        .or_else(|| object.get("binary_layout_evidence"))
        .or_else(|| object.get("layout_evidence"))
        .ok_or_else(|| invalid("inspect_binary_layout requires selected Evidence"))
}

fn selected_result(evidence: &Value) -> Result<&Value, Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("binary-layout Evidence must be an object"))?;
    object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .ok_or_else(|| invalid("binary-layout Evidence is missing normalized_result"))
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("binary-layout Evidence must be an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("selected Evidence is not inspect_binary_layout Evidence"));
    }
    require_text(object.get("evidence_id"), "evidence_id")?;
    validate_result(selected_result(evidence)?)?;
    validate_provenance(object)?;
    validate_limitations(object.get("limitations"))?;
    Ok(())
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("binary-layout normalized_result must be an object"))?;
    let encoded = serde_json::to_vec(result)
        .map_err(|_| invalid("binary-layout normalized_result is not serializable"))?;
    if encoded.len() > MAX_RESULT_BYTES {
        return Err(resource("binary-layout result exceeds the 64 MiB output limit"));
    }
    validate_artifact(object.get("artifact"))?;
    validate_optional_text(object.get("format"), "format")?;
    validate_optional_text(object.get("architecture"), "architecture")?;
    if let Some(limitations) = object.get("limitations") {
        validate_limitations(Some(limitations))?;
    }
    Ok(())
}

fn validate_artifact(value: Option<&Value>) -> Result<(), Failure> {
    let artifact = value
        .ok_or_else(|| invalid("binary-layout result must include artifact identity"))?
        .as_object()
        .ok_or_else(|| invalid("binary-layout artifact identity must be an object"))?;
    require_text(artifact.get("path"), "artifact.path")?;
    let digest = artifact
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("artifact.sha256 must be a SHA-256 text digest"))?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return Err(invalid("artifact.sha256 must contain 64 hexadecimal characters"));
    }
    let bytes = artifact
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("artifact.bytes must be a non-negative integer"))?;
    if bytes > MAX_RESULT_BYTES as u64 {
        return Err(resource("artifact.bytes exceeds the retained output limit"));
    }
    Ok(())
}

fn validate_provenance(evidence: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["provider", "provenance", "subject", "target"] {
        let Some(value) = evidence.get(field) else {
            continue;
        };
        if value.is_null() || value.is_object() || value.is_array() || value.is_string() {
            continue;
        }
        return Err(invalid(&format!("{field} provenance must be structured data")));
    }
    Ok(())
}

fn validate_optional_text(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_string() || value.is_object() || value.is_null() {
        if let Some(text) = value.as_str()
            && text.len() > MAX_TEXT_BYTES
        {
            return Err(resource(&format!("{field} exceeds the retained text limit")));
        }
        return Ok(());
    }
    Err(invalid(&format!("{field} must be structured data or text")))
}

fn validate_limitations(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("binary-layout limitations must be an array"))?;
    if values.len() > 4_096 {
        return Err(resource("binary-layout limitations exceed the item limit"));
    }
    for limitation in values {
        let text = limitation
            .as_str()
            .ok_or_else(|| invalid("binary-layout limitations must contain text"))?;
        if text.len() > MAX_TEXT_BYTES {
            return Err(resource("binary-layout limitation exceeds the text limit"));
        }
    }
    Ok(())
}

fn require_text(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let text = value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be non-empty text")))?;
    if text.len() > MAX_TEXT_BYTES {
        return Err(resource(&format!("{field} exceeds the retained text limit")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide captured inspect_binary_layout Evidence and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Request a smaller retained binary-layout result and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
