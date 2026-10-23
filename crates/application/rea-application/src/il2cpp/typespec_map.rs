//! Projection of IL2CPP TypeSpec rows and their generic type arguments.
//!
//! Binary metadata readers own decoding.  This module only joins normalized
//! rows supplied by a caller.  It deliberately keeps raw references and does
//! not derive a display name from a type index or generic argument. Explicit
//! TypeSpec-to-TypeSpec chains are followed with bounded cycle detection.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_typespecs";
const MAX_ROWS: usize = 200_000;

/// Join TypeSpec rows with type definitions and generic-instantiation rows.
///
/// Direct arrays are accepted, as are `metadata` wrappers.  A row that cannot
/// be resolved remains in the output with an explicit status and its original
/// source value.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let specs = rows(
        metadata,
        &["type_specs", "typeSpecifications", "typespecs"],
        "type_specs",
    )?;
    let types = rows_optional(
        metadata,
        &["types", "type_definitions", "typeDefinitions"],
        "types",
    )?;
    let instantiations = rows_optional(
        metadata,
        &[
            "generic_instantiations",
            "generic_classes",
            "genericClasses",
        ],
        "generic_instantiations",
    )?;
    let arguments = rows_optional(
        metadata,
        &["generic_arguments", "type_arguments", "genericArguments"],
        "generic_arguments",
    )?;

    let type_index = index_rows(types, "types")?;
    let instantiation_index = index_rows(instantiations, "generic_instantiations")?;
    let argument_index = index_rows(arguments, "generic_arguments")?;
    let type_spec_index = index_rows(specs, "type_specs")?;
    let mut diagnostics = Vec::new();
    let mut items = Vec::with_capacity(specs.len());
    let mut resolved_types = 0usize;
    let mut unresolved_types = 0usize;
    let mut resolved_instantiations = 0usize;
    let mut unresolved_instantiations = 0usize;
    let mut unresolved_argument_types = 0usize;
    let mut attached_arguments = 0usize;
    let mut incomplete_arguments = false;

    let mut spec_index_counts = BTreeMap::new();
    for (row, spec) in specs.iter().enumerate() {
        let object = object_row(spec, "type_specs", row)?;
        let index = row_index(
            object,
            &["type_spec_index", "typespec_index", "index"],
            "type_specs",
            row,
        )?
        .unwrap_or(row as u64);
        *spec_index_counts.entry(index).or_insert(0usize) += 1;
    }
    for (index, count) in spec_index_counts {
        if count > 1 {
            diagnostics.push(serde_json::json!({
                "kind": "duplicate_type_spec_index",
                "type_spec_index": index,
                "count": count,
            }));
        }
    }

    for (row, spec) in specs.iter().enumerate() {
        let object = object_row(spec, "type_specs", row)?;
        let spec_index = row_index(
            object,
            &["type_spec_index", "typespec_index", "index"],
            "type_specs",
            row,
        )?
        .unwrap_or(row as u64);
        let type_aliases =
            reference_aliases(object, &["type_index", "type_definition_index", "type"]);
        let type_reference = type_aliases.first().cloned().unwrap_or(Value::Null);
        let type_resolution = if aliases_contradict(&type_aliases) {
            ambiguous_alias_resolution(&type_aliases)
        } else {
            resolve_type_spec_reference(object, &type_reference, &type_index, &type_spec_index)
        };
        if type_resolution.get("status").and_then(Value::as_str) == Some("resolved") {
            resolved_types += 1;
        } else {
            unresolved_types += 1;
        }

        let instantiation_aliases = reference_aliases(
            object,
            &[
                "generic_instantiation_index",
                "generic_class_index",
                "generic_class",
            ],
        );
        let instantiation_reference = instantiation_aliases
            .first()
            .cloned()
            .unwrap_or(Value::Null);
        let instantiation_resolution = if aliases_contradict(&instantiation_aliases) {
            ambiguous_alias_resolution(&instantiation_aliases)
        } else {
            resolve_reference(&instantiation_reference, &instantiation_index)
        };
        let instantiation_row = instantiation_resolution
            .get("row")
            .and_then(Value::as_object)
            .cloned();
        if instantiation_resolution
            .get("status")
            .and_then(Value::as_str)
            == Some("resolved")
        {
            resolved_instantiations += 1;
        } else if !instantiation_reference.is_null() {
            unresolved_instantiations += 1;
        }

        let (argument_rows, argument_status, missing_arguments) = select_arguments(
            object,
            instantiation_row.as_ref(),
            &argument_index,
            arguments.len(),
        )?;
        incomplete_arguments |= argument_status == "partial";
        let (argument_rows, unresolved_in_arguments) =
            project_argument_rows(argument_rows, &type_index, &type_spec_index);
        attached_arguments += argument_rows.len();
        unresolved_argument_types += unresolved_in_arguments;
        if !missing_arguments.is_empty() {
            diagnostics.push(serde_json::json!({
                "kind": "missing_generic_arguments",
                "row": row,
                "type_spec_index": spec_index,
                "indices": missing_arguments,
            }));
        }
        if aliases_contradict(&type_aliases) {
            diagnostics.push(serde_json::json!({
                "kind": "contradictory_type_spec_aliases",
                "row": row,
                "type_spec_index": spec_index,
                "references": type_aliases,
            }));
        }
        if aliases_contradict(&instantiation_aliases) {
            diagnostics.push(serde_json::json!({
                "kind": "contradictory_generic_instantiation_aliases",
                "row": row,
                "type_spec_index": spec_index,
                "references": instantiation_aliases,
            }));
        }
        if unresolved_in_arguments > 0 {
            diagnostics.push(serde_json::json!({
                "kind": "unresolved_generic_argument_types",
                "row": row,
                "type_spec_index": spec_index,
                "count": unresolved_in_arguments,
            }));
        }

        items.push(serde_json::json!({
            "source_index": row,
            "type_spec_index": spec_index,
            "source": spec,
            "type_reference": type_reference,
            "type": type_resolution,
            "generic_instantiation_reference": instantiation_reference,
            "generic_instantiation": instantiation_resolution,
            "argument_status": argument_status,
            "arguments": argument_rows,
        }));
    }

    let status = if diagnostics.is_empty()
        && !incomplete_arguments
        && unresolved_types == 0
        && unresolved_instantiations == 0
        && unresolved_argument_types == 0
    {
        "complete"
    } else {
        "partial"
    };
    Ok(serde_json::json!({
        "status": status,
        "items": items,
        "diagnostics": diagnostics,
        "coverage": {
            "type_specs": specs.len(),
            "type_definitions": types.len(),
            "generic_instantiations": instantiations.len(),
            "generic_arguments": arguments.len(),
            "resolved_types": resolved_types,
            "unresolved_types": unresolved_types,
            "resolved_instantiations": resolved_instantiations,
            "unresolved_instantiations": unresolved_instantiations,
            "unresolved_argument_types": unresolved_argument_types,
            "attached_arguments": attached_arguments,
        }
    }))
}

fn project_argument_rows(
    rows: Vec<Value>,
    type_index: &BTreeMap<u64, Vec<&Value>>,
    type_spec_index: &BTreeMap<u64, Vec<&Value>>,
) -> (Vec<Value>, usize) {
    let mut unresolved = 0usize;
    let projected = rows
        .into_iter()
        .map(|source| {
            let reference = source
                .as_object()
                .and_then(|object| {
                    object
                        .get("type_index")
                        .or_else(|| object.get("type_definition_index"))
                        .or_else(|| object.get("type"))
                })
                .cloned()
                .unwrap_or(Value::Null);
            let resolution = if let Some(object) = source.as_object() {
                let nested_reference = object
                    .get("type_spec_index")
                    .or_else(|| object.get("typespec_index"))
                    .or_else(|| object.get("type_spec"));
                match nested_reference {
                    Some(value) if !value.is_null() && reference.is_null() => {
                        resolve_nested_type_reference(
                            value,
                            type_index,
                            type_spec_index,
                            &mut BTreeSet::new(),
                            true,
                        )
                    }
                    _ => resolve_reference(&reference, type_index),
                }
            } else {
                resolve_reference(&reference, type_index)
            };
            if resolution.get("status").and_then(Value::as_str) != Some("resolved") {
                unresolved += 1;
            }
            serde_json::json!({
                "source": source,
                "type_reference": reference,
                "type": resolution,
            })
        })
        .collect();
    (projected, unresolved)
}

fn reference_aliases(object: &Map<String, Value>, aliases: &[&str]) -> Vec<Value> {
    aliases
        .iter()
        .filter_map(|alias| object.get(*alias))
        .filter(|value| !value.is_null())
        .cloned()
        .collect()
}

fn aliases_contradict(values: &[Value]) -> bool {
    let Some(first) = values.first() else {
        return false;
    };

    values
        .iter()
        .skip(1)
        .any(|value| match (index_value(first), index_value(value)) {
            (Some(first), Some(value)) => first != value,
            _ => first != value,
        })
}

fn ambiguous_alias_resolution(values: &[Value]) -> Value {
    serde_json::json!({
        "status": "ambiguous",
        "reason": "contradictory aliases",
        "references": values,
    })
}

/// Resolve the concrete type named by a TypeSpec, including rows that point
/// through another TypeSpec before reaching a type definition.  The direct
/// type fields remain authoritative; nested references are only used when the
/// producer supplied no concrete type reference.
fn resolve_type_spec_reference(
    spec: &Map<String, Value>,
    direct_reference: &Value,
    type_index: &BTreeMap<u64, Vec<&Value>>,
    type_spec_index: &BTreeMap<u64, Vec<&Value>>,
) -> Value {
    if !direct_reference.is_null() {
        return resolve_reference(direct_reference, type_index);
    }

    let nested_reference = spec
        .get("nested_type_spec_index")
        .or_else(|| spec.get("type_spec_reference"))
        .cloned()
        .unwrap_or(Value::Null);
    if nested_reference.is_null() {
        return resolve_reference(direct_reference, type_index);
    }

    resolve_nested_type_reference(
        &nested_reference,
        type_index,
        type_spec_index,
        &mut BTreeSet::new(),
        true,
    )
}

/// Resolve a generic argument that names another TypeSpec before reaching a
/// concrete type definition. The visited set keeps malformed recursive rows
/// from becoming an unbounded traversal while retaining the original nested
/// row as the unresolved evidence.
fn resolve_nested_type_reference(
    reference: &Value,
    type_index: &BTreeMap<u64, Vec<&Value>>,
    type_spec_index: &BTreeMap<u64, Vec<&Value>>,
    visited: &mut BTreeSet<u64>,
    prefer_type_spec: bool,
) -> Value {
    let Some(index) = index_value(reference) else {
        return serde_json::json!({
            "status": if reference.is_null() { "missing" } else { "invalid" },
            "reference": reference,
        });
    };

    if !prefer_type_spec {
        if let Some(rows) = type_index.get(&index) {
            return if rows.len() == 1 {
                serde_json::json!({
                    "status": "resolved",
                    "index": index,
                    "reference": reference,
                    "row": rows[0],
                })
            } else {
                serde_json::json!({
                    "status": "ambiguous",
                    "index": index,
                    "reference": reference,
                    "rows": rows,
                })
            };
        }
    }

    let Some(spec_rows) = type_spec_index.get(&index) else {
        return serde_json::json!({
            "status": "unresolved",
            "index": index,
            "reference": reference,
        });
    };
    if spec_rows.len() != 1 {
        return serde_json::json!({
            "status": "ambiguous",
            "index": index,
            "reference": reference,
            "rows": spec_rows,
        });
    }

    let spec_row = spec_rows[0];
    if !visited.insert(index) {
        return serde_json::json!({
            "status": "unknown",
            "index": index,
            "reference": reference,
            "row": spec_row,
        });
    }

    let nested = spec_row.as_object().and_then(|object| {
        [
            ("type_index", false),
            ("type_definition_index", false),
            ("type", false),
            ("nested_type_spec_index", true),
            ("type_spec_reference", true),
        ]
        .iter()
        .find_map(|(key, is_type_spec)| object.get(*key).map(|value| (value, *is_type_spec)))
    });
    let Some((nested_reference, nested_is_type_spec)) = nested else {
        visited.remove(&index);
        return serde_json::json!({
            "status": "unknown",
            "index": index,
            "reference": reference,
            "row": spec_row,
        });
    };

    let mut resolution = resolve_nested_type_reference(
        nested_reference,
        type_index,
        type_spec_index,
        visited,
        nested_is_type_spec,
    );
    visited.remove(&index);
    if let Some(object) = resolution.as_object_mut() {
        object.insert("reference".into(), reference.clone());
    }
    resolution
}

fn select_arguments<'a>(
    spec: &Map<String, Value>,
    instantiation: Option<&Map<String, Value>>,
    argument_index: &BTreeMap<u64, Vec<&'a Value>>,
    argument_count: usize,
) -> Result<(Vec<Value>, &'static str, Vec<u64>), Failure> {
    let explicit = spec
        .get("generic_argument_indices")
        .or_else(|| spec.get("argument_indices"))
        .or_else(|| instantiation.and_then(|row| row.get("generic_argument_indices")))
        .or_else(|| instantiation.and_then(|row| row.get("argument_indices")));
    if let Some(value) = explicit {
        let indices = value
            .as_array()
            .ok_or_else(|| invalid("generic_argument_indices", "Expected an array"))?;
        let mut selected = Vec::new();
        let mut missing = Vec::new();
        let mut ambiguous = false;
        for (position, value) in indices.iter().enumerate() {
            let index = index_value(value).ok_or_else(|| {
                invalid(
                    &format!("generic_argument_indices[{position}]"),
                    "Expected a non-negative integer",
                )
            })?;
            match argument_index.get(&index) {
                Some(rows) => {
                    ambiguous |= rows.len() > 1;
                    selected.extend(rows.iter().map(|row| (*row).clone()));
                }
                None => missing.push(index),
            }
        }
        let status = if !missing.is_empty() || ambiguous {
            "partial"
        } else {
            "resolved"
        };
        return Ok((selected, status, missing));
    }

    let start = spec
        .get("generic_argument_start")
        .or_else(|| spec.get("argument_start"))
        .or_else(|| instantiation.and_then(|row| row.get("generic_argument_start")))
        .or_else(|| instantiation.and_then(|row| row.get("argument_start")));
    let count = spec
        .get("generic_argument_count")
        .or_else(|| spec.get("argument_count"))
        .or_else(|| instantiation.and_then(|row| row.get("generic_argument_count")))
        .or_else(|| instantiation.and_then(|row| row.get("argument_count")));
    let (Some(start), Some(count)) = (start, count) else {
        return Ok((
            Vec::new(),
            if argument_count == 0 {
                "empty"
            } else {
                "unknown"
            },
            Vec::new(),
        ));
    };
    let start = index_value(start)
        .ok_or_else(|| invalid("generic_argument_start", "Expected a non-negative integer"))?;
    let count = index_value(count)
        .ok_or_else(|| invalid("generic_argument_count", "Expected a non-negative integer"))?;
    let end = start
        .checked_add(count)
        .ok_or_else(|| invalid("generic_argument_range", "Range overflows"))?;
    let mut selected = Vec::new();
    let mut missing = Vec::new();
    let mut ambiguous = false;
    for index in start..end {
        match argument_index.get(&index) {
            Some(rows) => {
                ambiguous |= rows.len() > 1;
                selected.extend(rows.iter().map(|row| (*row).clone()));
            }
            None => missing.push(index),
        }
    }
    let status = if !missing.is_empty() || ambiguous {
        "partial"
    } else {
        "resolved"
    };
    Ok((selected, status, missing))
}

fn resolve_reference(reference: &Value, index: &BTreeMap<u64, Vec<&Value>>) -> Value {
    let Some(value) = index_value(reference) else {
        return serde_json::json!({
            "status": if reference.is_null() { "missing" } else { "unknown" },
            "reference": reference,
        });
    };
    match index.get(&value) {
        Some(rows) if rows.len() == 1 => {
            serde_json::json!({
                "status": "resolved",
                "index": value,
                "reference": reference,
                "row": rows[0],
            })
        }
        Some(rows) => serde_json::json!({
            "status": "ambiguous",
            "index": value,
            "reference": reference,
            "rows": rows,
        }),
        None => serde_json::json!({
            "status": "unresolved",
            "index": value,
            "reference": reference,
        }),
    }
}

fn index_rows<'a>(
    rows: &'a [Value],
    field: &str,
) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = object_row(value, field, row)?;
        let keys: &[&str] = match field {
            "generic_arguments" => &["argument_index", "generic_argument_index", "index"],
            "generic_instantiations" => &[
                "generic_instantiation_index",
                "generic_class_index",
                "index",
            ],
            "type_specs" => &["type_spec_index", "typespec_index", "index"],
            _ => &["metadata_index", "type_index", "index"],
        };
        let index_value = row_index(object, keys, field, row)?.unwrap_or(row as u64);
        index
            .entry(index_value)
            .or_insert_with(Vec::new)
            .push(value);
    }
    Ok(index)
}

fn row_index(
    object: &Map<String, Value>,
    keys: &[&str],
    field: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let Some((key, value)) = keys
        .iter()
        .find_map(|key| object.get(*key).map(|value| (*key, value)))
    else {
        return Ok(None);
    };

    if value.is_null() {
        return Ok(None);
    }

    index_value(value).map(Some).ok_or_else(|| {
        invalid(
            &format!("{field}[{row}].{key}"),
            "Expected a non-negative integer index",
        )
    })
}

/// Decode an index while retaining the original JSON value in every projected
/// row. Metadata captures commonly encode offsets as decimal or hexadecimal
/// strings; treating those as unknown would lose an otherwise exact identity.
fn index_value(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?.trim();
        let digits = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
        match digits {
            Some(digits) if !digits.is_empty() => u64::from_str_radix(digits, 16).ok(),
            _ if !text.is_empty() => text.parse::<u64>().ok(),
            _ => None,
        }
    })
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = aliases.iter().find_map(|alias| object.get(*alias));
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP TypeSpec row limit",
        ));
    }
    Ok(rows)
}

fn rows_optional<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    match aliases.iter().find_map(|alias| object.get(*alias)) {
        None => Ok(&[]),
        Some(value) => {
            let rows = value
                .as_array()
                .ok_or_else(|| invalid(field, "Expected an array"))?;
            if rows.len() > MAX_ROWS {
                return Err(invalid(
                    field,
                    "Collection exceeds the IL2CPP TypeSpec row limit",
                ));
            }
            Ok(rows)
        }
    }
}

fn object_row<'a>(
    value: &'a Value,
    field: &str,
    row: usize,
) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid(&format!("{field}[{row}]"), "Expected an object"))
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP TypeSpec mapping input is invalid.".into(),
        false,
        "Supply normalized TypeSpec, type-definition, and generic-argument rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
