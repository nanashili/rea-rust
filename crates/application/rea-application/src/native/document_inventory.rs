//! Read-only projection of a retained provider document inventory.
//!
//! Provider adapters decide which documents are active or ready. This module
//! preserves their order and identity facts without deduplicating or reopening
//! a provider session.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_documents";
const MAX_DOCUMENTS: usize = 200_000;

/// Project retained document rows into the stable document-identity result.
pub fn list(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Input must be an object"))?;
    let documents = object
        .get("documents")
        .or_else(|| object.get("rows"))
        .or_else(|| object.get("result"))
        .ok_or_else(|| invalid("A retained document inventory is required"))?;
    let rows = documents
        .as_array()
        .ok_or_else(|| invalid("documents must be an array"))?;
    if rows.len() > MAX_DOCUMENTS {
        return Err(invalid("documents exceed the retained inventory limit"));
    }

    let mut identities = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        identities.push(identity(row, index)?);
    }
    Ok(Value::Array(
        identities.into_iter().map(Value::String).collect(),
    ))
}

/// Application-layer alias used by retained Evidence callers.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    list(input)
}

/// Validate a provider result before retaining it as Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = list(input)?;
    if result != expected {
        return Err(invalid(
            "Document result does not match retained source rows",
        ));
    }
    Ok(result)
}

fn identity(row: &Value, index: usize) -> Result<String, Failure> {
    if let Some(value) = row.as_str() {
        if !value.is_empty() {
            return Ok(value.to_owned());
        }
        return Err(invalid(&format!("documents[{index}] must be non-empty")));
    }
    let object = row
        .as_object()
        .ok_or_else(|| invalid(&format!("documents[{index}] must be text or an object")))?;
    for key in ["path", "relative_path", "document_id", "id", "name"] {
        if let Some(value) = object
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Ok(value.to_owned());
        }
    }
    Err(invalid(&format!(
        "documents[{index}] has no non-empty identity field"
    )))
}

/// Keep a stable failure helper for callers that need to expose provenance.
pub fn invalid_with_provenance(reason: &str, source: Option<&Map<String, Value>>) -> Failure {
    let mut details = BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("reason", Detail::Text(reason.into())),
    ]);
    if let Some(source) = source {
        if let Ok(raw) = serde_json::value::to_raw_value(source) {
            details.insert("source", Detail::Raw(raw));
        }
    }
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded retained document inventory and retry.".into(),
        details,
    )
}

fn invalid(reason: &str) -> Failure {
    invalid_with_provenance(reason, None)
}
