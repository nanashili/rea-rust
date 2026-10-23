//! Projection of IL2CPP generic containers and their parameter constraints.
//!
//! Metadata readers own binary decoding.  This module consumes normalized rows
//! and joins them by the explicit indices supplied by that reader.  It never
//! guesses whether an owner is a type or a method, and retains invalid or
//! ambiguous references as observations in the result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "project_il2cpp_generic_context";
const MAX_ROWS: usize = 200_000;

/// Attach generic parameters and constraints to their exact container rows.
///
/// Accepted input uses direct arrays or `metadata`/`binary` wrappers.  The
/// metadata side contains `generic_containers`, `generic_parameters`, and
/// optionally `generic_parameter_constraints` or `constraints`.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    validate_input_shape(root)?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let containers = rows(
        metadata,
        &["generic_containers", "genericContainers"],
        "generic_containers",
    )?;
    let parameters = rows(
        metadata,
        &["generic_parameters", "genericParameters"],
        "generic_parameters",
    )?;
    let constraints = rows_optional(
        metadata,
        &[
            "generic_parameter_constraints",
            "genericParameterConstraints",
            "constraints",
        ],
    )?;

    let parameter_index = index_parameter_rows(parameters)?;
    let constraint_index = index_constraint_rows(constraints)?;
    let mut container_items = Vec::with_capacity(containers.len());
    let mut diagnostics = Vec::new();
    let mut attached_parameters = 0usize;
    let mut unresolved_parameters = 0usize;
    let mut parameter_containers: BTreeMap<u64, Vec<usize>> = BTreeMap::new();

    for (container_row, container) in containers.iter().enumerate() {
        let object = object_row(container, "generic_containers", container_row)?;
        let container_index = required_index_alias(
            object,
            &[
                "generic_container_index",
                "container_index",
                "source_index",
                "index",
            ],
            "index",
            container_row,
        )?;
        let owner = owner_fact(object, container_row, &mut diagnostics)?;
        let start = optional_index(
            object,
            &[
                "generic_parameter_start",
                "parameter_start",
                "genericParameterStart",
            ],
        )?;
        let count = optional_index(
            object,
            &[
                "type_argc",
                "parameter_count",
                "generic_parameter_count",
                "typeArgc",
            ],
        )?;

        let mut attached = Vec::new();
        let mut missing = Vec::new();
        if let (Some(start), Some(count)) = (start, count) {
            let end = start.checked_add(count);
            match end {
                Some(end) => {
                    for parameter_index_value in start..end {
                        parameter_containers
                            .entry(parameter_index_value)
                            .or_default()
                            .push(container_row);

                        match parameter_index.get(&parameter_index_value) {
                            Some(rows) => {
                                for parameter_row in rows {
                                    attached.push(parameter_row.clone());
                                    attached_parameters += 1;
                                }
                            }
                            None => {
                                missing.push(Value::from(parameter_index_value));
                                unresolved_parameters += 1;
                            }
                        }
                    }
                }
                None => diagnostics.push(json_diagnostic(
                    "range_overflow",
                    container_row,
                    "Generic parameter range overflows",
                )),
            }
        } else {
            diagnostics.push(json_diagnostic(
                "missing_range",
                container_row,
                "Generic container does not provide both parameter start and count",
            ));
        }

        if !missing.is_empty() {
            diagnostics.push(serde_json::json!({
                "kind": "missing_parameter_rows",
                "row": container_row,
                "container_index": container_index,
                "indices": missing,
            }));
        }

        container_items.push(serde_json::json!({
            "source_index": container_row,
            "container_index": container_index,
            "source": container,
            "owner": owner,
            "parameter_start": start.map(Value::from).unwrap_or(Value::Null),
            "parameter_count": count.map(Value::from).unwrap_or(Value::Null),
            "parameters": attached,
        }));
    }

    let parameter_items = parameters
        .iter()
        .enumerate()
        .map(|(row, parameter)| {
            project_parameter(row, parameter, &constraint_index, &mut diagnostics)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let duplicate_owners = duplicate_owner_count(&container_items);
    if duplicate_owners > 0 {
        diagnostics.push(serde_json::json!({
            "kind": "duplicate_owner",
            "count": duplicate_owners,
            "meaning": "Multiple generic containers retain the same explicit owner",
        }));
    }
    let duplicate_parameter_indices = duplicate_index_count(&parameter_index);
    if duplicate_parameter_indices > 0 {
        diagnostics.push(serde_json::json!({
            "kind": "duplicate_parameter_index",
            "count": duplicate_parameter_indices,
            "meaning": "Multiple generic parameter rows retain the same explicit index",
        }));
    }
    let duplicate_constraint_indices = duplicate_index_count(&constraint_index);
    if duplicate_constraint_indices > 0 {
        diagnostics.push(serde_json::json!({
            "kind": "duplicate_constraint_index",
            "count": duplicate_constraint_indices,
            "meaning": "Multiple generic constraint rows retain the same explicit index",
        }));
    }

    append_parameter_overlap_diagnostics(&parameter_containers, &mut diagnostics);

    let status = if diagnostics.is_empty() {
        "complete"
    } else {
        "partial"
    };
    Ok(serde_json::json!({
        "status": status,
        "containers": container_items,
        "parameters": parameter_items,
        "constraints": constraints,
        "diagnostics": diagnostics,
        "coverage": {
            "generic_containers": containers.len(),
            "generic_parameters": parameters.len(),
            "constraints": constraints.len(),
            "attached_parameter_rows": attached_parameters,
            "unresolved_parameter_references": unresolved_parameters,
            "duplicate_owner_count": duplicate_owners,
        }
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    const DIRECT_FIELDS: &[&str] = &[
        "generic_containers",
        "genericContainers",
        "generic_parameters",
        "genericParameters",
        "generic_parameter_constraints",
        "genericParameterConstraints",
        "constraints",
    ];
    const WRAPPED_FIELDS: &[&str] = &["metadata", "binary"];

    if root.contains_key("metadata") {
        reject_unknown_fields(root, WRAPPED_FIELDS, "input")?;
        let metadata = root
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        reject_unknown_fields(metadata, DIRECT_FIELDS, "metadata")?;
        if let Some(binary) = root.get("binary") {
            if !binary.is_object() {
                return Err(invalid("binary", "Expected an object"));
            }
        }
        return Ok(());
    }

    reject_unknown_fields(root, DIRECT_FIELDS, "input")
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(
            &format!("{field}.{unknown}"),
            "Unknown field is not allowed",
        ));
    }
    Ok(())
}

fn project_parameter(
    row: usize,
    parameter: &Value,
    constraints: &BTreeMap<u64, Vec<&Value>>,
    diagnostics: &mut Vec<Value>,
) -> Result<Value, Failure> {
    let object = object_row(parameter, "generic_parameters", row)?;
    let parameter_index = optional_index(
        object,
        &["generic_parameter_index", "parameter_index", "index"],
    )?
    .unwrap_or(row as u64);
    let constraint_start = optional_index(object, &["constraints_start", "constraint_start"])?;
    let constraint_count = optional_index(object, &["constraints_count", "constraint_count"])?;
    let mut selected = Vec::new();
    let mut missing = Vec::new();
    if let (Some(start), Some(count)) = (constraint_start, constraint_count) {
        let end = start.checked_add(count);
        if let Some(end) = end {
            for index in start..end {
                if let Some(rows) = constraints.get(&index) {
                    selected.extend(rows.iter().map(|constraint| (*constraint).clone()));
                } else {
                    missing.push(Value::from(index));
                }
            }
        } else {
            diagnostics.push(json_diagnostic(
                "constraint_range_overflow",
                row,
                "Constraint range overflows",
            ));
        }
    }
    if !missing.is_empty() {
        diagnostics.push(serde_json::json!({
            "kind": "missing_constraint_rows",
            "row": row,
            "parameter_index": parameter_index,
            "indices": missing,
        }));
    }
    Ok(serde_json::json!({
        "source_index": row,
        "parameter_index": parameter_index,
        "source": parameter,
        "constraints": selected,
    }))
}

fn index_constraint_rows<'a>(rows: &'a [Value]) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let constraint_index = value
            .as_object()
            .map(|object| {
                optional_index(
                    object,
                    &[
                        "constraint_index",
                        "generic_parameter_constraint_index",
                        "index",
                        "source_index",
                    ],
                )
            })
            .transpose()?
            .flatten()
            .unwrap_or(row as u64);
        index
            .entry(constraint_index)
            .or_insert_with(Vec::new)
            .push(value);
    }
    Ok(index)
}

fn owner_fact(
    object: &Map<String, Value>,
    row: usize,
    diagnostics: &mut Vec<Value>,
) -> Result<Value, Failure> {
    for (field, allow_minus_one) in [
        ("type_index", false),
        ("method_index", false),
        ("owner_index", true),
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let valid = value
            .as_i64()
            .is_some_and(|index| index >= 0 || (allow_minus_one && index == -1));
        if !valid {
            diagnostics.push(json_diagnostic(
                "malformed_owner_identity",
                row,
                "Owner identity index is malformed; ownership remains unknown",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        }
    }

    let type_index = owner_identity_index(object, "type_index", false, row)?;
    let method_index = owner_identity_index(object, "method_index", false, row)?;

    let mut owner_kind_values = Vec::new();
    for key in ["owner_kind", "ownerKind"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        let Some(kind) = value.as_str() else {
            diagnostics.push(json_diagnostic(
                "malformed_owner_kind",
                row,
                "Owner kind is malformed; ownership remains unknown",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        };
        owner_kind_values.push(kind.to_owned());
    }
    if let Some(kind) = owner_kind_values.first() {
        if owner_kind_values.iter().any(|candidate| candidate != kind) {
            diagnostics.push(json_diagnostic(
                "conflicting_owner_kind",
                row,
                "Owner kind aliases disagree",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        }
        let kind = kind.as_str();
        if !matches!(kind, "type" | "method" | "unknown") {
            diagnostics.push(json_diagnostic(
                "unknown_owner_kind",
                row,
                "Owner kind is outside the known set",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        }
        let index = owner_identity_index(object, "owner_index", true, row)?;
        let alias_index = match kind {
            "type" => type_index,
            "method" => method_index,
            _ => None,
        };
        if index.is_some() && alias_index.is_some() && index != alias_index {
            diagnostics.push(json_diagnostic(
                "conflicting_owner_identity",
                row,
                "Owner kind/index aliases disagree",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        }
        if type_index.is_some() && method_index.is_some() {
            diagnostics.push(json_diagnostic(
                "ambiguous_owner_identity",
                row,
                "Generic container declares both type and method owners",
            ));
            return Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}));
        }
        return Ok(serde_json::json!({
            "kind": kind,
            "index": index.or(alias_index),
        }));
    }
    if type_index.is_some() && method_index.is_some() {
        diagnostics.push(json_diagnostic(
            "ambiguous_owner_identity",
            row,
            "Generic container declares both type and method owners",
        ));
        return Ok(serde_json::json!({
            "kind": "unknown",
            "index": Value::Null,
        }));
    }
    if let Some(index) = type_index {
        return Ok(serde_json::json!({"kind": "type", "index": index}));
    }
    if let Some(index) = method_index {
        return Ok(serde_json::json!({"kind": "method", "index": index}));
    }
    diagnostics.push(json_diagnostic(
        "unknown_owner",
        row,
        "Generic container has no explicit type or method owner",
    ));
    Ok(serde_json::json!({"kind": "unknown", "index": Value::Null}))
}

fn owner_identity_index(
    object: &Map<String, Value>,
    field: &str,
    allow_minus_one: bool,
    row: usize,
) -> Result<Option<i64>, Failure> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let Some(index) = value.as_i64() else {
        return Err(invalid(
            &format!("generic_containers[{row}].{field}"),
            "Expected an integer owner index",
        ));
    };
    if index < 0 && (!allow_minus_one || index != -1) {
        return Err(invalid(
            &format!("generic_containers[{row}].{field}"),
            "Owner index must be non-negative or -1",
        ));
    }
    Ok(Some(index))
}

fn index_parameter_rows<'a>(rows: &'a [Value]) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = object_row(value, "generic_parameters", row)?;
        let parameter_index = optional_index(
            object,
            &["generic_parameter_index", "parameter_index", "index"],
        )?
        .unwrap_or(row as u64);
        index
            .entry(parameter_index)
            .or_insert_with(Vec::new)
            .push(value);
    }
    Ok(index)
}

fn duplicate_owner_count(containers: &[Value]) -> usize {
    let mut owners = BTreeMap::new();
    for container in containers {
        if let Some(owner) = container
            .get("owner")
            .filter(|owner| has_explicit_owner_identity(owner))
        {
            *owners.entry(owner.to_string()).or_insert(0usize) += 1;
        }
    }
    owners
        .values()
        .filter(|count| **count > 1)
        .map(|count| count - 1)
        .sum()
}

fn has_explicit_owner_identity(owner: &Value) -> bool {
    let Some(object) = owner.as_object() else {
        return false;
    };
    matches!(
        object.get("kind").and_then(Value::as_str),
        Some("type" | "method")
    ) && object.get("index").is_some_and(|index| !index.is_null())
}

fn duplicate_index_count(index: &BTreeMap<u64, Vec<&Value>>) -> usize {
    index
        .values()
        .filter_map(|rows| rows.len().checked_sub(1))
        .sum()
}

fn append_parameter_overlap_diagnostics(
    parameter_containers: &BTreeMap<u64, Vec<usize>>,
    diagnostics: &mut Vec<Value>,
) {
    for (parameter_index, containers) in parameter_containers {
        if containers.len() < 2 {
            continue;
        }

        diagnostics.push(serde_json::json!({
            "kind": "overlapping_parameter_ranges",
            "parameter_index": parameter_index,
            "container_rows": containers,
            "message": "Generic container parameter ranges overlap",
        }));
    }
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let rows =
        aliased_rows(object, aliases, field)?.ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP generic row limit",
        ));
    }
    Ok(rows)
}

fn rows_optional<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
) -> Result<&'a [Value], Failure> {
    let rows = aliased_rows(object, aliases, "constraints")?.unwrap_or(&[]);
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "constraints",
            "Collection exceeds the IL2CPP generic row limit",
        ));
    }
    Ok(rows)
}

fn aliased_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a [Value]>, Failure> {
    let mut selected = None;
    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(field, "Expected an array"))?;
        if let Some(existing) = selected {
            if existing != rows {
                return Err(invalid(
                    field,
                    "Row aliases disagree; generic context ownership is ambiguous",
                ));
            }
        } else {
            selected = Some(rows.as_slice());
        }
    }
    Ok(selected)
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

fn required_index_alias(
    object: &Map<String, Value>,
    keys: &[&str],
    field: &str,
    row: usize,
) -> Result<u64, Failure> {
    let values = collect_index_aliases(object, keys, false, |key| format!("{field}[{row}].{key}"))?;
    match values.first().copied() {
        Some(index) if values.iter().all(|value| *value == index) => Ok(index),
        Some(_) => Err(invalid(
            &format!("{field}[{row}]"),
            "Conflicting index aliases are not allowed",
        )),
        None => Err(invalid(
            &format!("{field}[{row}]"),
            "Missing generic container index",
        )),
    }
}

fn optional_index(object: &Map<String, Value>, keys: &[&str]) -> Result<Option<u64>, Failure> {
    let values = collect_index_aliases(object, keys, true, |key| key.to_string())?;
    match values.first().copied() {
        Some(index) if values.iter().all(|value| *value == index) => Ok(Some(index)),
        Some(_) => Err(invalid(
            "index",
            "Conflicting index aliases are not allowed",
        )),
        None => Ok(None),
    }
}

fn collect_index_aliases(
    object: &Map<String, Value>,
    keys: &[&str],
    allow_missing: bool,
    path_for_key: impl Fn(&str) -> String,
) -> Result<Vec<u64>, Failure> {
    let mut values = Vec::new();

    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        if allow_missing && (value.is_null() || value.as_i64() == Some(-1)) {
            continue;
        }

        let Some(index) = value.as_u64() else {
            return Err(invalid(
                &path_for_key(key),
                if allow_missing {
                    "Expected a non-negative integer or null"
                } else {
                    "Expected a non-negative integer"
                },
            ));
        };
        values.push(index);
    }

    Ok(values)
}

fn json_diagnostic(kind: &str, row: usize, message: &str) -> Value {
    serde_json::json!({"kind": kind, "row": row, "message": message})
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP generic context input is invalid.".into(),
        false,
        "Supply normalized IL2CPP generic rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
