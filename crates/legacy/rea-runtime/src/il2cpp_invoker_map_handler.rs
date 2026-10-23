//! Captured/static boundary for `map_il2cpp_invokers`.
//!
//! Invoker indices, pointer rows, and managed associations are supplied by
//! the caller from an existing capture. This adapter only delegates the
//! projection and therefore has no artifact, provider, or target authority.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Exact public operation exposed by this adapter.
pub const OPERATION: &str = il2cpp::invoker_map::OPERATION;

/// Project caller-supplied IL2CPP invoker facts without live access.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already-selected operation without opening an artifact or
/// acquiring a process, provider, or target.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_request_shape(input).map_err(tag_failure)?;
    il2cpp::invoker_map::project(input).map_err(tag_failure)
}

/// Enforce the public direct or wrapped envelope before delegating row
/// interpretation to the application owner. In particular, an explicitly
/// supplied null is rejected as malformed rather than being treated as an
/// omitted metadata or binary object.
fn validate_request_shape(input: &Value) -> Result<(), Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("Input must be an object."))?;

    if root.contains_key("metadata") || root.contains_key("binary") {
        if root.len() != 2 || !root.contains_key("metadata") || !root.contains_key("binary") {
            return Err(invalid(
                "Wrapped input must contain only metadata and binary objects.",
            ));
        }

        let metadata = require_object(root, "metadata")?;
        let binary = require_object(root, "binary")?;
        validate_scope_keys(metadata, METADATA_FIELDS, "metadata")?;
        validate_binary_scope(binary)?;
        return Ok(());
    }

    validate_scope_keys(root, DIRECT_FIELDS, "direct")?;
    validate_required_collection(root, INDEX_ALIASES, "invoker_indices")?;
    validate_required_collection(root, POINTER_ALIASES, "invoker_pointers")?;
    Ok(())
}

fn validate_binary_scope(object: &Map<String, Value>) -> Result<(), Failure> {
    validate_scope_keys(object, BINARY_FIELDS, "binary")?;
    validate_required_collection(object, INDEX_ALIASES, "invoker_indices")?;
    validate_required_collection(object, POINTER_ALIASES, "invoker_pointers")?;
    Ok(())
}

fn validate_scope_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), Failure> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(invalid(&format!(
            "{scope} input contains unsupported field {field}."
        )));
    }
    Ok(())
}

fn validate_required_collection(
    object: &Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<(), Failure> {
    let supplied = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    if supplied.is_empty() {
        return Err(invalid(&format!(
            "{field} requires one of its supported aliases."
        )));
    }
    if supplied.len() > 1 {
        return Err(invalid(&format!("{field} has multiple aliases.")));
    }
    if !supplied[0].1.is_array() {
        return Err(invalid(&format!("{} must be an array.", supplied[0].0)));
    }
    Ok(())
}

fn require_object<'a>(
    root: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    root.get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{field} must be an object.")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide direct or metadata-wrapped IL2CPP invoker rows and retry.".to_owned(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

const INDEX_ALIASES: &[&str] = &[
    "invoker_indices",
    "invoker_index_table",
    "invoker_index_rows",
];
const POINTER_ALIASES: &[&str] = &["invoker_pointers", "invokers", "invoker_pointer_rows"];
const METADATA_FIELDS: &[&str] = &["methods", "method_definitions", "types", "type_definitions"];
const BINARY_FIELDS: &[&str] = &[
    "invoker_indices",
    "invoker_index_table",
    "invoker_index_rows",
    "invoker_pointers",
    "invokers",
    "invoker_pointer_rows",
    "generic_invokers",
    "generic_invoker_facts",
];
const DIRECT_FIELDS: &[&str] = &[
    "invoker_indices",
    "invoker_index_table",
    "invoker_index_rows",
    "invoker_pointers",
    "invokers",
    "invoker_pointer_rows",
    "methods",
    "method_definitions",
    "types",
    "type_definitions",
    "generic_invokers",
    "generic_invoker_facts",
];

fn tag_failure(mut failure: Failure) -> Failure {
    failure.detail("operation", Detail::Text(OPERATION.into()));
    failure.detail("authority", Detail::Text("offline_capture_only".into()));
    failure
}
