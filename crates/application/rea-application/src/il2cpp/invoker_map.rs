//! Correlates caller-supplied IL2CPP invoker facts.
//!
//! Invoker indices and native pointers are separate identities.  This module
//! only joins normalized captures; it does not infer an invoker from a method
//! row, or treat an invoker pointer as a method body address.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "map_il2cpp_invokers";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Project invoker-index rows, native invoker pointers, managed methods/types,
/// and generic-invoker facts while preserving ambiguous associations.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    validate_input_shape(root)?;

    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let indices = rows(
        binary,
        &[
            "invoker_indices",
            "invoker_index_table",
            "invoker_index_rows",
        ],
        "invoker_indices",
    )?;
    let pointers = rows(
        binary,
        &["invoker_pointers", "invokers", "invoker_pointer_rows"],
        "invoker_pointers",
    )?;
    let methods = optional_rows(metadata, &["methods", "method_definitions"], "methods")?;
    let types = optional_rows(metadata, &["types", "type_definitions"], "types")?;
    let generic = optional_rows(
        binary,
        &["generic_invokers", "generic_invoker_facts"],
        "generic_invokers",
    )?;

    let pointer_map = index_rows_optional(pointers, "invoker_pointers", pointer_key)?;
    let method_map = index_rows_optional(methods, "methods", method_key)?;
    let method_metadata_map = index_rows_optional(methods, "methods", method_metadata_key)?;
    let generic_map = index_rows(generic, "generic_invokers", generic_key)?;

    let mut items = Vec::with_capacity(indices.len());
    let mut seen = BTreeSet::new();
    let mut ambiguous = 0usize;
    let mut unresolved = 0usize;
    for (row, source) in indices.iter().enumerate() {
        let object = source
            .as_object()
            .ok_or_else(|| invalid_row("invoker_indices", row, "Expected an object"))?;
        let index = invoker_index(object)
            .ok_or_else(|| invalid_row("invoker_indices", row, "invoker_index is required"))?;
        let identity_conflict =
            conflicting_indices(object, &["invoker_index", "invokerIndex", "index", "slot"]);
        let method_identity_conflict = conflicting_indices(
            object,
            &[
                "method_index",
                "methodIndex",
                "method_definition_index",
                "methodDefinitionIndex",
            ],
        );
        let duplicate_index = !seen.insert(index);
        let pointer = pointer_map.get(&index).cloned().unwrap_or_default();
        let method_metadata_identity_conflict = source_method_index(object)
            .and_then(|method_index| method_metadata_map.get(&method_index))
            .is_some_and(|rows| {
                rows_have_identity_conflict(
                    Some(rows),
                    &[
                        "metadata_index",
                        "metadataIndex",
                        "method_index",
                        "methodIndex",
                        "method_definition_index",
                        "methodDefinitionIndex",
                        "index",
                    ],
                )
            });
        let method = associated_methods(
            method_map.get(&index),
            (!method_identity_conflict && !method_metadata_identity_conflict)
                .then(|| source_method_index(object))
                .flatten()
                .and_then(|method_index| method_metadata_map.get(&method_index)),
        );
        let generic_fact = associated(generic_map.get(&index));
        let pointer_state = if pointer.is_empty() {
            "unmapped"
        } else if pointer.len() > 1 {
            "ambiguous"
        } else if rows_have_identity_conflict(
            pointer_map.get(&index),
            &["invoker_index", "invokerIndex", "index", "slot"],
        ) {
            "ambiguous"
        } else if pointer_address_space_conflicts(pointer[0]) {
            "ambiguous"
        } else if pointer_has_address(pointer[0]) {
            "mapped"
        } else {
            "unknown"
        };
        let resolution = if duplicate_index
            || identity_conflict
            || method_identity_conflict
            || method_metadata_identity_conflict
            || pointer_state == "ambiguous"
            || method.len() > 1
            || rows_have_identity_conflict(
                method_map.get(&index),
                &["invoker_index", "invokerIndex"],
            )
            || rows_have_identity_conflict(
                generic_map.get(&index),
                &[
                    "invoker_index",
                    "invokerIndex",
                    "generic_invoker_index",
                    "genericInvokerIndex",
                ],
            )
            || generic_fact.len() > 1
        {
            ambiguous += 1;
            "ambiguous"
        } else if pointer_state == "unmapped" || method.is_empty() {
            unresolved += 1;
            "unresolved"
        } else if pointer_state == "unknown" || generic_fact.is_empty() {
            unresolved += 1;
            "unknown"
        } else {
            "resolved"
        };
        items.push(serde_json::json!({
            "invoker_index": index,
            "source": source,
            "invoker_pointers": pointer,
            "methods": method,
            "types": associated_types(&method, types),
            "generic_invokers": generic_fact,
            "resolution": resolution
        }));
    }

    Ok(serde_json::json!({
        "status": if ambiguous == 0 && unresolved == 0 { "complete" } else { "partial" },
        "items": items,
        "coverage": {
            "invoker_indices": indices.len(), "invoker_pointers": pointers.len(),
            "methods": methods.len(), "types": types.len(), "generic_invokers": generic.len(),
            "ambiguous": ambiguous, "unresolved": unresolved
        }
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    let wrapped = root.contains_key("metadata") || root.contains_key("binary");

    if wrapped {
        reject_unknown_fields(root, &["metadata", "binary"], "input")?;

        let metadata = root
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        let binary = root
            .get("binary")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("binary", "Expected an object"))?;

        reject_unknown_fields(
            metadata,
            &["methods", "method_definitions", "types", "type_definitions"],
            "metadata",
        )?;
        reject_unknown_fields(
            binary,
            &[
                "invoker_indices",
                "invoker_index_table",
                "invoker_index_rows",
                "invoker_pointers",
                "invokers",
                "invoker_pointer_rows",
                "generic_invokers",
                "generic_invoker_facts",
            ],
            "binary",
        )?;
    } else {
        reject_unknown_fields(
            root,
            &[
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
            ],
            "input",
        )?;
    }

    Ok(())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(name) = object
        .keys()
        .find(|name| !allowed.iter().any(|candidate| candidate == name))
    {
        return Err(invalid(field, &format!("Unknown field `{name}`")));
    }

    Ok(())
}

fn associated<'a>(rows: Option<&'a Vec<&'a Value>>) -> Vec<Value> {
    rows.map(|values| values.iter().map(|value| (*value).clone()).collect())
        .unwrap_or_default()
}

/// Resolve a method through its direct invoker identity first, then through
/// the stable metadata method identity carried by the invoker-index row.
/// A row can appear in both maps when a producer includes both identities;
/// retain it once so that duplicate aliases do not manufacture ambiguity.
fn associated_methods<'a>(
    direct: Option<&'a Vec<&'a Value>>,
    metadata: Option<&'a Vec<&'a Value>>,
) -> Vec<Value> {
    let mut values = Vec::new();
    for row in direct.into_iter().chain(metadata) {
        for value in row {
            if !values.iter().any(|existing| existing == *value) {
                values.push((*value).clone());
            }
        }
    }
    values
}

fn rows_have_identity_conflict(rows: Option<&Vec<&Value>>, names: &[&str]) -> bool {
    rows.is_some_and(|rows| {
        rows.iter().any(|value| {
            value
                .as_object()
                .is_some_and(|object| conflicting_indices(object, names))
        })
    })
}

fn associated_types(methods: &[Value], types: &[Value]) -> Vec<Value> {
    let indices: BTreeSet<u64> = methods
        .iter()
        .filter_map(|method| method.as_object())
        .flat_map(|object| {
            ["type_index", "typeIndex", "declaring_type", "declaringType"]
                .into_iter()
                .filter_map(|name| object.get(name).and_then(parse_index))
        })
        .collect();
    types
        .iter()
        .filter(|value| {
            value
                .as_object()
                .and_then(|object| {
                    [
                        "type_index",
                        "typeIndex",
                        "metadata_index",
                        "metadataIndex",
                        "index",
                    ]
                    .into_iter()
                    .find_map(|name| object.get(name).and_then(parse_index))
                })
                .is_some_and(|index| indices.contains(&index))
        })
        .cloned()
        .collect()
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value =
        select_rows(object, aliases, field)?.ok_or_else(|| invalid(field, "Expected an array"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP invoker row limit",
        ));
    }
    Ok(rows)
}

fn optional_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let Some(value) = select_rows(object, aliases, field)? else {
        return Ok(&[]);
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the IL2CPP row limit"));
    }
    Ok(rows)
}

fn select_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let present = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();

    if present.len() > 1 {
        return Err(invalid(
            field,
            "Multiple aliases were supplied for the same collection",
        ));
    }

    Ok(present.first().map(|(_, value)| *value))
}

fn index_rows<'a>(
    rows: &'a [Value],
    field: &str,
    key: fn(&Map<String, Value>, usize) -> Option<u64>,
) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut output = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row(field, row, "Expected an object"))?;
        let index = key(object, row)
            .ok_or_else(|| invalid_row(field, row, "A non-negative index is required"))?;
        output.entry(index).or_insert_with(Vec::new).push(value);
    }
    Ok(output)
}

fn index_rows_optional<'a>(
    rows: &'a [Value],
    field: &str,
    key: fn(&Map<String, Value>, usize) -> Option<u64>,
) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut output = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row(field, row, "Expected an object"))?;
        let Some(index) = key(object, row) else {
            continue;
        };
        output.entry(index).or_insert_with(Vec::new).push(value);
    }
    Ok(output)
}
fn invoker_index(object: &Map<String, Value>) -> Option<u64> {
    ["invoker_index", "invokerIndex", "index", "slot"]
        .into_iter()
        .find_map(|name| object.get(name).and_then(parse_index))
}
fn pointer_key(object: &Map<String, Value>, _row: usize) -> Option<u64> {
    // Pointer-table row order is not an invoker identity.  Requiring the
    // captured key keeps a reordered or filtered table from being joined to
    // the wrong invoker index.
    invoker_index(object)
}
fn method_key(object: &Map<String, Value>, _row: usize) -> Option<u64> {
    ["invoker_index", "invokerIndex"]
        .into_iter()
        .find_map(|name| object.get(name).and_then(parse_index))
}

fn method_metadata_key(object: &Map<String, Value>, _row: usize) -> Option<u64> {
    [
        "metadata_index",
        "metadataIndex",
        "method_index",
        "methodIndex",
        "method_definition_index",
        "methodDefinitionIndex",
        "index",
    ]
    .into_iter()
    .find_map(|name| object.get(name).and_then(parse_index))
}

fn source_method_index(object: &Map<String, Value>) -> Option<u64> {
    [
        "method_index",
        "methodIndex",
        "method_definition_index",
        "methodDefinitionIndex",
    ]
    .into_iter()
    .find_map(|name| object.get(name).and_then(parse_index))
}

fn conflicting_indices(object: &Map<String, Value>, names: &[&str]) -> bool {
    let mut values = BTreeSet::new();
    let mut malformed = false;

    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };

        let Some(index) = parse_index(value) else {
            malformed = true;
            continue;
        };

        values.insert(index);
    }

    malformed || values.len() > 1
}
fn generic_key(object: &Map<String, Value>, _row: usize) -> Option<u64> {
    [
        "invoker_index",
        "invokerIndex",
        "generic_invoker_index",
        "genericInvokerIndex",
    ]
    .into_iter()
    .find_map(|name| object.get(name).and_then(parse_index))
}
fn pointer_has_address(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("address"))
        .and_then(parse_address)
        .is_some_and(|address| address != 0)
}

fn pointer_address_space_conflicts(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };

    let mut values = BTreeSet::new();
    for name in ["address_space", "addressSpace", "space"] {
        if let Some(address_space) = object.get(name).and_then(Value::as_str) {
            values.insert(address_space);
        }
    }

    values.len() > 1
}

fn parse_address(value: &Value) -> Option<u64> {
    parse_index(value)
}

fn parse_index(value: &Value) -> Option<u64> {
    if let Some(index) = value.as_u64() {
        return (index <= MAX_SAFE_INTEGER).then_some(index);
    }

    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }

    let (radix, digits) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or((10, text), |digits| (16, digits));
    if digits.is_empty() {
        return None;
    }

    u64::from_str_radix(digits, radix)
        .ok()
        .filter(|index| *index <= MAX_SAFE_INTEGER)
}
fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), reason)
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP invoker mapping input is invalid.".into(),
        false,
        "Supply normalized invoker tables and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
