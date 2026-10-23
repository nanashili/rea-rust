//! Offline selection of a component from an already parsed Android package.
//!
//! The Android package parser owns binary XML decoding and manifest source
//! coverage. This module only selects one retained component and carries the
//! parser's values, nulls, source offsets, and limitations through unchanged.
//! It never opens an APK or reparses manifest bytes.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_android_manifest_component";
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Select an exact `(kind, name)` identity from an owner-produced package
/// report. The returned value is a borrowed component, so no fields are
/// normalized or reinterpreted by this boundary.
pub fn select_component<'a>(
    package: &'a Value,
    kind: &str,
    name: &str,
) -> Result<&'a Value, Failure> {
    let components = package_components(package)?;
    let matches = components
        .iter()
        .filter(|component| component_identity(component) == Some((kind, name)))
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(selection_failure(format!(
            "No manifest component matched kind {kind:?} and name {name:?}."
        ))),
        [component] => Ok(component),
        _ => Err(selection_failure(format!(
            "Manifest component selection was ambiguous: {kind:?} {name:?} occurs {} times.",
            matches.len()
        ))),
    }
}

/// Project one selected component while retaining the parsed manifest source.
/// `package` must be the complete retained result from the Android package
/// owner, including its `manifest`, `components`, and optional `limitations`.
pub fn inspect_component(package: &Value, kind: &str, name: &str) -> Result<Value, Failure> {
    if kind.is_empty() || name.is_empty() {
        return Err(invalid("component kind and name must be non-empty"));
    }
    let component = select_component(package, kind, name)?.clone();
    let package_object = package
        .as_object()
        .expect("package_components validates the package object");
    let manifest = package_object.get("manifest").cloned();
    let limitations = package_object
        .get("limitations")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let source = source_evidence(&component, manifest.as_ref());
    let result = json!({
        "kind": kind,
        "name": name,
        "component": component,
        "match_count": 1,
        "manifest": manifest,
        "source": source,
        "limitations": limitations,
        "selection": {"kind": kind, "name": name, "identity": "exact"},
    });
    let size = serde_json::to_vec(&result)
        .map_err(|_| resource("unable to serialize manifest component result"))?
        .len();
    if size > MAX_OUTPUT_BYTES {
        return Err(resource(
            "manifest component result exceeds the output budget",
        ));
    }
    Ok(result)
}

/// JSON adapter for retained package results. This accepts the package result
/// directly and never accepts a path or raw manifest bytes.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    reject_unknown_fields(object)?;
    let package = object
        .get("package")
        .ok_or_else(|| invalid("package must be a retained parsed package result"))?;
    let kind = required_string(object, "kind")?;
    let name = required_string(object, "name")?;
    inspect_component(package, kind, name)
}

fn package_components(package: &Value) -> Result<&Vec<Value>, Failure> {
    let object = package
        .as_object()
        .ok_or_else(|| invalid("retained package result must be an object"))?;
    object
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained package result must contain components"))
}

fn component_identity(component: &Value) -> Option<(&str, &str)> {
    let object = component.as_object()?;
    Some((object.get("kind")?.as_str()?, object.get("name")?.as_str()?))
}

fn source_evidence(component: &Value, manifest: Option<&Value>) -> Value {
    let component_offset = component
        .as_object()
        .and_then(|object| first_field(object, &["source_offset", "sourceOffset"]))
        .cloned()
        .unwrap_or(Value::Null);
    let intent_offsets = component
        .as_object()
        .and_then(|object| first_field(object, &["intent_filters", "intentFilters"]))
        .and_then(Value::as_array)
        .map(|filters| {
            filters
                .iter()
                .filter_map(|filter| {
                    let object = filter.as_object()?;
                    first_field(object, &["source_offset", "sourceOffset"]).cloned()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "manifest": manifest.cloned().unwrap_or(Value::Null),
        "component_source_offset": component_offset,
        "intent_filter_source_offsets": intent_offsets,
        "source_owner": "retained_android_package_parser",
    })
}

/// Read an owner-provided field without converting or merging representations.
/// The snake_case form is emitted by the Rust parser; the camelCase form is
/// retained for callers that pass a TypeScript-produced package record.
fn first_field<'a>(object: &'a Map<String, Value>, names: &[&str]) -> Option<&'a Value> {
    names.iter().find_map(|name| object.get(*name))
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{field} must be a non-empty string")))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "package" | "kind" | "name"))
    {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn selection_failure(message: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message,
        true,
        "Select one exact manifest component identity and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text("component".into())),
        ]),
    )
}

fn invalid(message: impl Into<String>) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the retained package and selection arguments and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "memory",
        message.into(),
        true,
        "Select a smaller retained package result and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
