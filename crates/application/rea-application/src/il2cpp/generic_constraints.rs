//! Detailed, lossless projection of IL2CPP generic parameter constraints.
//!
//! This is deliberately separate from generic-method instantiation mapping.
//! It reports the metadata references that were supplied by a decoder and
//! never turns a type index into a guessed type name.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap};

pub const OPERATION: &str = "project_il2cpp_generic_constraints";
const MAX_ROWS: usize = 200_000;

/// Attach constraint rows to their exact generic-parameter rows.
///
/// Input accepts direct arrays or a `metadata` object containing
/// `generic_parameters`, `generic_parameter_constraints` (or `constraints`),
/// and optional `generic_containers`.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = match root.get("metadata") {
        Some(Value::Object(metadata)) => metadata,
        Some(_) => return Err(invalid("metadata", "Expected an object")),
        None => root,
    };
    let parameters = rows(
        metadata,
        &["generic_parameters", "genericParameters"],
        "generic_parameters",
    )?;
    let constraints = rows(
        metadata,
        &[
            "generic_parameter_constraints",
            "genericParameterConstraints",
            "constraints",
        ],
        "constraints",
    )?;
    let containers = optional_rows(
        metadata,
        &["generic_containers", "genericContainers"],
        "generic_containers",
    )?;
    let type_specs = optional_rows(
        metadata,
        &[
            "type_specs",
            "typeSpecifications",
            "typeSpecs",
            "typespecs",
            "type_specifications",
        ],
        "type_specs",
    )?;
    let type_definitions = optional_rows(
        metadata,
        &["type_definitions", "typeDefinitions", "types"],
        "type_definitions",
    )?;

    let mut diagnostics = Vec::new();
    let mut by_parameter: HashMap<u64, Vec<ConstraintProjection>> = HashMap::new();
    let mut projections_by_row = vec![None; constraints.len()];
    let mut constraint_keys: HashMap<String, usize> = HashMap::new();
    let mut duplicate_constraint_keys = 0usize;

    for (row, constraint) in constraints.iter().enumerate() {
        let object = object_row(constraint, "constraints", row)?;
        let index = read_index(
            object,
            &["generic_parameter_index", "parameter_index", "parameter"],
        );
        let parameter_index = index.value;
        let key = format!(
            "{}:{}:{}",
            parameter_index.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            owner_key(object),
            type_reference(constraint)
        );
        if constraint_keys.insert(key, row).is_some() {
            duplicate_constraint_keys += 1;
        }
        if let Some(parameter_index) = parameter_index {
            let mut projection = ConstraintProjection::new(row, constraint, object);
            let reference_conflict = conflicting_type_reference(constraint);
            let (descriptor, descriptor_ambiguous) = if reference_conflict {
                // Keep a contradictory identity unknown. Resolving one alias
                // would silently attach the constraint to an arbitrary type.
                (Value::Null, true)
            } else {
                resolve_type_descriptor(&projection.type_reference, type_specs, type_definitions)
            };
            projection.type_descriptor = descriptor;
            if reference_conflict {
                diagnostics.push(serde_json::json!({
                    "kind": "conflicting_constraint_type_reference",
                    "row": row,
                    "type_reference": projection.type_reference.clone(),
                    "message": "Constraint type reference aliases disagree or are malformed",
                }));
            }
            if projection.type_descriptor.is_null()
                && object.get("type").is_some()
                && !object.contains_key("type_index")
                && !object.contains_key("constraint_type_index")
                && !object.contains_key("typeIndex")
                && !object.contains_key("constraintTypeIndex")
                && !object.contains_key("type_spec_index")
                && !object.contains_key("typeSpecIndex")
                && !object.contains_key("type_definition_index")
                && !object.contains_key("typeDefinitionIndex")
            {
                projection.type_descriptor = object.get("type").cloned().unwrap_or(Value::Null);
            }
            if descriptor_ambiguous {
                diagnostics.push(serde_json::json!({
                    "kind": "ambiguous_constraint_type_descriptor",
                    "row": row,
                    "type_reference": projection.type_reference.clone(),
                    "message": "Multiple supplied type descriptors match the constraint reference",
                }));
            }
            if projection.type_descriptor.is_null()
                && !projection.type_reference.is_null()
                && (!type_specs.is_empty() || !type_definitions.is_empty())
            {
                diagnostics.push(serde_json::json!({
                    "kind": "missing_constraint_type_descriptor",
                    "row": row,
                    "type_reference": projection.type_reference.clone(),
                }));
            }
            projections_by_row[row] = Some(projection.clone());
            by_parameter
                .entry(parameter_index)
                .or_default()
                .push(projection);
        } else {
            projections_by_row[row] = Some(ConstraintProjection::new(row, constraint, object));
            diagnostics.push(serde_json::json!({
                "kind": "malformed_constraint_parameter_index",
                "row": row,
                "value": index.raw,
                "message": "Constraint parameter index is absent or malformed",
            }));
        }
    }

    let mut parameter_items = Vec::with_capacity(parameters.len());
    let mut attached = 0usize;
    let mut missing_parameter_references = 0usize;
    let mut parameter_key_counts = HashMap::<u64, usize>::new();
    for (row, parameter) in parameters.iter().enumerate() {
        let object = object_row(parameter, "generic_parameters", row)?;
        let index_read = optional_index(
            object,
            &["generic_parameter_index", "parameter_index", "index"],
        );
        if let Some(index) = index_read
            .value
            .or_else(|| (index_read.state == "absent").then_some(row as u64))
        {
            *parameter_key_counts.entry(index).or_default() += 1;
        }
    }
    for (row, parameter) in parameters.iter().enumerate() {
        let object = object_row(parameter, "generic_parameters", row)?;
        let index_read = optional_index(
            object,
            &["generic_parameter_index", "parameter_index", "index"],
        );
        let index = index_read
            .value
            .or_else(|| (index_read.state == "absent").then_some(row as u64));
        if index_read.state == "malformed" {
            diagnostics.push(serde_json::json!({
                "kind": "malformed_parameter_index",
                "row": row,
                "value": index_read.raw.clone(),
            }));
        }
        let container = resolve_container(object, containers, row, &mut diagnostics);
        let mut selected = index
            .and_then(|index| by_parameter.get(&index))
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|constraint| {
                matches!(
                    owner_relation(&owner_fields(object), &constraint.owner),
                    "exact" | "ambiguous"
                )
            })
            .collect::<Vec<_>>();
        append_range_constraints(
            object,
            row,
            &owner_fields(object),
            &projections_by_row,
            &mut selected,
            &mut diagnostics,
        )?;
        if index.is_some_and(|index| {
            by_parameter.get(&index).is_some_and(|constraints| {
                constraints.iter().any(|constraint| {
                    owner_relation(&owner_fields(object), &constraint.owner) == "conflict"
                })
            })
        }) {
            diagnostics.push(serde_json::json!({
                "kind": "conflicting_constraint_owner",
                "row": row,
                "parameter_index": index,
                "message": "Constraint rows with this index belong to a different owner",
            }));
        }
        if selected
            .iter()
            .any(|constraint| constraint.owner_status == "ambiguous")
        {
            diagnostics.push(serde_json::json!({
                "kind": "ambiguous_constraint_owner",
                "row": row,
                "parameter_index": index,
            }));
        }
        attached += selected.len();
        let constraint_rows = selected
            .iter()
            .map(ConstraintProjection::as_value)
            .collect::<Vec<_>>();
        let parameter_status = match index {
            None => "unresolved",
            Some(index) => match parameter_key_counts.get(&index).copied().unwrap_or(0) {
                0 | 1 => "resolved",
                _ => {
                    diagnostics.push(serde_json::json!({
                        "kind": "ambiguous_parameter_index",
                        "parameter_index": index,
                        "row": row,
                        "message": "Multiple generic-parameter rows share this index",
                    }));
                    "ambiguous"
                }
            },
        };
        parameter_items.push(serde_json::json!({
            "source_index": row,
            "parameter_index": index.map(Value::from).unwrap_or(Value::Null),
            "parameter_index_source": index_read.raw,
            "owner": owner_fields(object),
            "container": container,
            "source": parameter,
            "flags": object.get("flags").cloned().unwrap_or(Value::Null),
            "position": object.get("num").or_else(|| object.get("position")).cloned().unwrap_or(Value::Null),
            "resolution": parameter_status,
            "constraints": constraint_rows,
        }));
        if selected.is_empty() && has_constraint_range(object) {
            missing_parameter_references += 1;
            diagnostics.push(serde_json::json!({
                "kind": "missing_constraint_rows",
                "parameter_index": index.map(Value::from).unwrap_or(Value::Null),
                "row": row,
                "message": "Parameter declares constraints but none reference it",
            }));
        }
    }

    let mut orphan_constraints = Vec::new();
    let parameter_indices: std::collections::BTreeSet<u64> = parameters
        .iter()
        .enumerate()
        .filter_map(|(row, value)| {
            value
                .as_object()
                .and_then(|object| {
                    optional_index(
                        object,
                        &["generic_parameter_index", "parameter_index", "index"],
                    )
                    .value
                })
                .or_else(|| {
                    let index = optional_index(
                        value.as_object().unwrap_or(&Map::new()),
                        &["generic_parameter_index", "parameter_index", "index"],
                    );
                    (index.state == "absent").then_some(row as u64)
                })
        })
        .collect();
    for (row, constraint) in constraints.iter().enumerate() {
        let object = object_row(constraint, "constraints", row)?;
        let index = read_index(
            object,
            &["generic_parameter_index", "parameter_index", "parameter"],
        );
        if index.value.is_none() || !parameter_indices.contains(&index.value.unwrap()) {
            orphan_constraints.push(Value::from(row));
            diagnostics.push(serde_json::json!({
                "kind": "orphan_constraint",
                "row": row,
                "parameter_index": index.value,
                "parameter_index_source": index.raw.clone(),
            }));
        }
    }

    if duplicate_constraint_keys > 0 {
        diagnostics.push(serde_json::json!({
            "kind": "duplicate_constraint_row",
            "count": duplicate_constraint_keys,
        }));
    }
    let status = if diagnostics.is_empty() {
        "complete"
    } else {
        "partial"
    };
    Ok(serde_json::json!({
        "status": status,
        "parameters": parameter_items,
        "constraints": constraints,
        "diagnostics": diagnostics,
        "coverage": {
            "parameters": parameters.len(),
            "constraints": constraints.len(),
            "attached": attached,
            "orphan_constraints": orphan_constraints.len(),
            "orphan_constraint_rows": orphan_constraints,
            "missing_parameter_references": missing_parameter_references,
        }
    }))
}

fn resolve_container(
    object: &Map<String, Value>,
    containers: &[Value],
    row: usize,
    diagnostics: &mut Vec<Value>,
) -> Value {
    let index = read_index(object, &["generic_container_index", "container_index"]);
    let Some(index) = index.value else {
        if index.state == "malformed" {
            diagnostics.push(serde_json::json!({
                "kind": "malformed_container_index",
                "row": row,
                "value": index.raw,
            }));
        }
        return Value::Null;
    };
    if let Some(container) = containers.get(index as usize) {
        return serde_json::json!({
            "index": index,
            "source": container,
            "owner": container_owner(container),
        });
    }
    diagnostics.push(serde_json::json!({
        "kind": "out_of_range_container",
        "row": row,
        "container_index": index,
    }));
    serde_json::json!({"index": index, "source": null})
}

fn type_reference(value: &Value) -> Value {
    let Some(object) = value.as_object() else {
        return Value::Null;
    };
    object
        .get("type_index")
        .or_else(|| object.get("typeIndex"))
        .or_else(|| object.get("constraint_type_index"))
        .or_else(|| object.get("constraintTypeIndex"))
        .or_else(|| object.get("type_spec_index"))
        .or_else(|| object.get("typeSpecIndex"))
        .or_else(|| object.get("typespec_index"))
        .or_else(|| object.get("typespecIndex"))
        .or_else(|| object.get("type_definition_index"))
        .or_else(|| object.get("typeDefinitionIndex"))
        .or_else(|| object.get("typedef_index"))
        .or_else(|| object.get("type"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn resolve_type_descriptor(
    reference: &Value,
    type_specs: &[Value],
    type_definitions: &[Value],
) -> (Value, bool) {
    if let Some(object) = reference.as_object() {
        let has_index = [
            "type_index",
            "typeIndex",
            "constraint_type_index",
            "constraintTypeIndex",
            "type_spec_index",
            "typeSpecIndex",
            "typespec_index",
            "typespecIndex",
            "type_definition_index",
            "typeDefinitionIndex",
            "typedef_index",
            "index",
        ]
        .iter()
        .any(|key| object.contains_key(*key));
        if !has_index {
            return (reference.clone(), false);
        }
    }

    let Some(index) = reference_index(reference) else {
        return (Value::Null, false);
    };
    let kind = reference_kind(reference);
    let candidates = match kind {
        Some(TypeReferenceKind::Spec) => type_specs.iter().collect::<Vec<_>>(),
        Some(TypeReferenceKind::Definition) => type_definitions.iter().collect::<Vec<_>>(),
        None => type_specs
            .iter()
            .chain(type_definitions.iter())
            .collect::<Vec<_>>(),
    };
    let explicit_matches = candidates
        .into_iter()
        .filter(|descriptor| {
            descriptor.as_object().and_then(|object| {
                read_index(
                    object,
                    &[
                        "type_index",
                        "typeIndex",
                        "type_spec_index",
                        "typeSpecIndex",
                        "type_definition_index",
                        "typeDefinitionIndex",
                        "typedef_index",
                        "index",
                    ],
                )
                .value
            }) == Some(index)
        })
        .cloned()
        .collect::<Vec<_>>();
    if !explicit_matches.is_empty() {
        let ambiguous = explicit_matches.len() > 1;
        return (
            if ambiguous {
                Value::Array(explicit_matches)
            } else {
                explicit_matches[0].clone()
            },
            ambiguous,
        );
    }

    // A numeric reference without an explicit identity can use the decoder's
    // positional rows only when there is a single candidate.  For typed
    // references, absence of an explicit matching identity remains unknown;
    // falling back to a different row family would silently join a TypeSpec
    // constraint to a TypeDef (or vice versa).
    let mut positional_matches = Vec::new();
    match kind {
        Some(TypeReferenceKind::Spec) => {
            if let Some(candidate) = type_specs.get(index as usize) {
                positional_matches.push(candidate.clone());
            }
        }
        Some(TypeReferenceKind::Definition) => {
            if let Some(candidate) = type_definitions.get(index as usize) {
                positional_matches.push(candidate.clone());
            }
        }
        None => {
            if let Some(candidate) = type_specs.get(index as usize) {
                positional_matches.push(candidate.clone());
            }
            if let Some(candidate) = type_definitions.get(index as usize) {
                positional_matches.push(candidate.clone());
            }
        }
    }
    match positional_matches.len() {
        0 => (Value::Null, false),
        1 => (positional_matches[0].clone(), false),
        _ => (Value::Array(positional_matches), true),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TypeReferenceKind {
    Spec,
    Definition,
}

fn reference_kind(reference: &Value) -> Option<TypeReferenceKind> {
    let object = reference.as_object()?;
    if [
        "type_spec_index",
        "typeSpecIndex",
        "typespec_index",
        "typespecIndex",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
    {
        return Some(TypeReferenceKind::Spec);
    }
    if [
        "type_definition_index",
        "typeDefinitionIndex",
        "typedef_index",
    ]
    .iter()
    .any(|key| object.contains_key(*key))
    {
        return Some(TypeReferenceKind::Definition);
    }
    None
}

fn reference_index(reference: &Value) -> Option<u64> {
    if let Ok(Some(index)) = parse_index_value(reference) {
        return Some(index);
    }
    let object = reference.as_object()?;
    [
        "type_index",
        "typeIndex",
        "constraint_type_index",
        "constraintTypeIndex",
        "type_spec_index",
        "typeSpecIndex",
        "typespec_index",
        "typespecIndex",
        "type_definition_index",
        "typeDefinitionIndex",
        "typedef_index",
        "index",
    ]
    .iter()
    .find_map(|key| {
        object
            .get(*key)
            .and_then(|value| parse_index_value(value).ok().flatten())
    })
}

fn conflicting_type_reference(reference: &Value) -> bool {
    let Some(object) = reference.as_object() else {
        return false;
    };
    let aliases = [
        "type_index",
        "typeIndex",
        "constraint_type_index",
        "constraintTypeIndex",
        "type_spec_index",
        "typeSpecIndex",
        "typespec_index",
        "typespecIndex",
        "type_definition_index",
        "typeDefinitionIndex",
        "typedef_index",
        "index",
    ];
    let mut resolved = None;
    for alias in aliases {
        let Some(value) = object.get(alias) else {
            continue;
        };
        let Ok(candidate) = parse_index_value(value) else {
            return true;
        };
        let Some(candidate) = candidate else {
            continue;
        };
        if resolved.is_some_and(|previous| previous != candidate) {
            return true;
        }
        resolved = Some(candidate);
    }

    let nested_type = object.get("type");
    let nested_type_conflict = nested_type.is_some_and(conflicting_type_reference);
    let nested_index = nested_type.and_then(|value| {
        if value.is_object() {
            reference_index(value)
        } else {
            parse_index_value(value).ok().flatten()
        }
    });
    let nested_identity_conflict = resolved
        .zip(nested_index)
        .is_some_and(|(outer, inner)| outer != inner);

    nested_type_conflict || nested_identity_conflict || conflicting_type_domains(reference)
}

fn conflicting_type_domains(reference: &Value) -> bool {
    let (has_type_spec_index, has_type_definition_index) = type_reference_domains(reference);
    has_type_spec_index && has_type_definition_index
}

fn type_reference_domains(reference: &Value) -> (bool, bool) {
    let Some(object) = reference.as_object() else {
        return (false, false);
    };

    let has_type_spec_index = [
        "type_spec_index",
        "typeSpecIndex",
        "typespec_index",
        "typespecIndex",
    ]
    .iter()
    .any(|key| object.contains_key(*key));
    let has_type_definition_index = [
        "type_definition_index",
        "typeDefinitionIndex",
        "typedef_index",
    ]
    .iter()
    .any(|key| object.contains_key(*key));

    let nested_domains = object
        .get("type")
        .map_or((false, false), |nested| type_reference_domains(nested));

    (
        has_type_spec_index || nested_domains.0,
        has_type_definition_index || nested_domains.1,
    )
}

fn owner_fields(object: &Map<String, Value>) -> Value {
    if let Some(owner) = object.get("owner").and_then(Value::as_object) {
        let kind = owner
            .get("kind")
            .or_else(|| owner.get("owner_kind"))
            .and_then(Value::as_str)
            .map(normalize_owner_kind)
            .unwrap_or("unknown");
        let reference = owner
            .get("reference")
            .or_else(|| owner.get("index"))
            .or_else(|| owner.get("token"))
            .cloned()
            .unwrap_or(Value::Null);
        return serde_json::json!({
            "kind": kind,
            "reference": reference,
            "resolution": if kind == "unknown" || reference.is_null() {
                "ambiguous"
            } else {
                "resolved"
            },
        });
    }
    let kind = object
        .get("owner_kind")
        .or_else(|| object.get("container_kind"))
        .or_else(|| object.get("generic_container_kind"))
        .or_else(|| object.get("context_kind"))
        .or_else(|| object.get("generic_kind"))
        .and_then(Value::as_str)
        .map(normalize_owner_kind)
        .unwrap_or("unknown");
    let reference = object
        .get("owner")
        .or_else(|| object.get("owner_reference"))
        .or_else(|| object.get("owner_token"))
        .or_else(|| object.get("generic_container_index"))
        .or_else(|| object.get("container_index"))
        .or_else(|| object.get("type_container_index"))
        .or_else(|| object.get("method_container_index"))
        .cloned()
        .unwrap_or(Value::Null);
    let reference_status = match parse_index_value(&reference) {
        Ok(Some(_)) => "resolved",
        Ok(None) if kind == "unknown" => "unknown",
        Ok(None) => "unresolved",
        Err(_) if reference.is_string() => "resolved",
        Err(_) => "malformed",
    };
    let resolution = if kind == "unknown" || reference_status == "malformed" {
        "ambiguous"
    } else if reference_status == "resolved" {
        "resolved"
    } else {
        "unresolved"
    };
    serde_json::json!({
        "kind": kind,
        "reference": reference,
        "resolution": resolution,
    })
}

fn container_owner(value: &Value) -> Value {
    value.as_object().map(owner_fields).unwrap_or_else(
        || serde_json::json!({"kind": "unknown", "reference": null, "resolution": "ambiguous"}),
    )
}

fn normalize_owner_kind(kind: &str) -> &str {
    match kind {
        "type" | "Type" | "type_container" | "TypeDefinition" => "type",
        "method" | "Method" | "method_container" | "GenericMethod" => "method",
        _ => "unknown",
    }
}

fn owner_key(object: &Map<String, Value>) -> String {
    owner_fields(object).to_string()
}

fn owner_relation(parameter_owner: &Value, constraint_owner: &Value) -> &'static str {
    let Some(parameter) = parameter_owner.as_object() else {
        return "ambiguous";
    };
    let Some(constraint) = constraint_owner.as_object() else {
        return "ambiguous";
    };
    let parameter_kind = parameter.get("kind").and_then(Value::as_str);
    let constraint_kind = constraint.get("kind").and_then(Value::as_str);
    if parameter_kind != Some("unknown")
        && constraint_kind != Some("unknown")
        && parameter_kind != constraint_kind
    {
        return "conflict";
    }
    let parameter_reference = parameter.get("reference");
    let constraint_reference = constraint.get("reference");
    if let (Some(parameter_reference), Some(constraint_reference)) =
        (parameter_reference, constraint_reference)
    {
        if !parameter_reference.is_null()
            && !constraint_reference.is_null()
            && parameter_reference != constraint_reference
        {
            return "conflict";
        }
    }
    if parameter.get("resolution").and_then(Value::as_str) == Some("resolved")
        && constraint.get("resolution").and_then(Value::as_str) == Some("resolved")
    {
        "exact"
    } else {
        "ambiguous"
    }
}

fn has_constraint_range(object: &Map<String, Value>) -> bool {
    object
        .get("constraints_count")
        .or_else(|| object.get("constraint_count"))
        .is_some()
}

fn append_range_constraints(
    object: &Map<String, Value>,
    parameter_row: usize,
    parameter_owner: &Value,
    projections_by_row: &[Option<ConstraintProjection>],
    selected: &mut Vec<ConstraintProjection>,
    diagnostics: &mut Vec<Value>,
) -> Result<(), Failure> {
    let start = read_index(object, &["constraints_start", "constraint_start"]);
    let count = read_index(object, &["constraints_count", "constraint_count"]);
    if start.state == "malformed" || count.state == "malformed" {
        diagnostics.push(serde_json::json!({
            "kind": "malformed_constraint_range",
            "row": parameter_row,
            "start": start.raw,
            "count": count.raw,
        }));
        return Ok(());
    }
    let (Some(start), Some(count)) = (start.value, count.value) else {
        return Ok(());
    };
    let Some(end) = start.checked_add(count) else {
        diagnostics.push(serde_json::json!({
            "kind": "constraint_range_overflow",
            "row": parameter_row,
            "start": start,
            "count": count,
        }));
        return Ok(());
    };

    let mut missing = Vec::new();
    for constraint_index in start..end {
        let Some(row) = usize::try_from(constraint_index)
            .ok()
            .and_then(|index| projections_by_row.get(index))
            .and_then(Option::as_ref)
        else {
            missing.push(Value::from(constraint_index));
            continue;
        };
        let relation = owner_relation(parameter_owner, &row.owner);
        if relation == "conflict" {
            diagnostics.push(serde_json::json!({
                "kind": "conflicting_constraint_owner",
                "row": parameter_row,
                "constraint_row": row.source_index,
                "message": "A ranged constraint belongs to a different owner",
            }));
            continue;
        }
        if !selected
            .iter()
            .any(|selected_row| selected_row.source_index == row.source_index)
        {
            selected.push(row.clone());
        }
    }
    if !missing.is_empty() {
        diagnostics.push(serde_json::json!({
            "kind": "missing_constraint_rows",
            "row": parameter_row,
            "indices": missing,
        }));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct IndexRead {
    value: Option<u64>,
    raw: Value,
    state: &'static str,
}

#[derive(Clone, Debug)]
struct ConstraintProjection {
    source_index: usize,
    source: Value,
    type_reference: Value,
    type_descriptor: Value,
    owner: Value,
    owner_status: &'static str,
}

impl ConstraintProjection {
    fn new(source_index: usize, source: &Value, object: &Map<String, Value>) -> Self {
        let owner = owner_fields(object);
        let owner_status = match owner.get("resolution").and_then(Value::as_str) {
            Some("exact") => "exact",
            Some("ambiguous") => "ambiguous",
            Some("missing") => "missing",
            _ => "unknown",
        };
        Self {
            source_index,
            source: source.clone(),
            type_reference: type_reference(source),
            type_descriptor: Value::Null,
            owner,
            owner_status,
        }
    }

    fn as_value(&self) -> Value {
        serde_json::json!({
            "source_index": self.source_index,
            "source": self.source,
            "type_reference": self.type_reference,
            "type_descriptor": self.type_descriptor,
        })
    }
}

fn optional_index(object: &Map<String, Value>, keys: &[&str]) -> IndexRead {
    read_index(object, keys)
}

fn read_index(object: &Map<String, Value>, keys: &[&str]) -> IndexRead {
    let mut resolved = None;
    let mut raw_values = Vec::new();

    for key in keys {
        if let Some(value) = object.get(*key) {
            let parsed = match parse_index_value(value) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return IndexRead {
                        value: None,
                        raw: value.clone(),
                        state: "malformed",
                    };
                }
            };
            raw_values.push(value.clone());
            if let Some(parsed) = parsed {
                if resolved.is_some_and(|previous| previous != parsed) {
                    return IndexRead {
                        value: None,
                        raw: Value::Array(raw_values),
                        state: "malformed",
                    };
                }
                resolved = Some(parsed);
            }
        }
    }

    if let Some(value) = resolved {
        return IndexRead {
            value: Some(value),
            raw: raw_values.first().cloned().unwrap_or(Value::Null),
            state: "resolved",
        };
    }
    IndexRead {
        value: None,
        raw: raw_values.first().cloned().unwrap_or(Value::Null),
        state: "absent",
    }
}

fn parse_index_value(value: &Value) -> Result<Option<u64>, ()> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(number) = value.as_u64() {
        return Ok(Some(number));
    }
    if let Some(text) = value.as_str() {
        let text = text.trim();
        if text.is_empty() || text.starts_with('-') {
            return Err(());
        }
        let parsed = if text.starts_with("0x") || text.starts_with("0X") {
            u64::from_str_radix(&text[2..], 16)
        } else {
            text.parse::<u64>()
        };
        return parsed.map(Some).map_err(|_| ());
    }
    let Some(object) = value.as_object() else {
        return Err(());
    };

    // Captured metadata can retain a reference object rather than flattening
    // its identity into the row. Resolve only recognized identity keys so a
    // reordered capture joins by its stable metadata index instead of by the
    // current array position. Multiple keys must agree; otherwise the
    // reference is deliberately left malformed and cannot silently attach.
    let mut resolved: Option<u64> = None;
    let mut saw_key = false;
    for key in [
        "generic_parameter_index",
        "parameter_index",
        "constraint_type_index",
        "type_index",
        "type_spec_index",
        "type_definition_index",
        "index",
        "id",
    ] {
        let Some(candidate) = object.get(key) else {
            continue;
        };
        saw_key = true;
        let candidate = parse_index_value(candidate)?;
        match (resolved, candidate) {
            (None, value) => resolved = value,
            (Some(previous), Some(value)) if previous == value => {}
            _ => return Err(()),
        }
    }
    if saw_key { Ok(resolved) } else { Err(()) }
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = selected_alias_value(object, aliases, field)?;
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP generic row limit",
        ));
    }
    Ok(rows)
}

fn optional_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    match selected_alias_value(object, aliases, field)? {
        None => Ok(&[]),
        Some(value) => {
            let rows = value
                .as_array()
                .ok_or_else(|| invalid(field, "Expected an array"))?;
            if rows.len() > MAX_ROWS {
                return Err(invalid(
                    field,
                    "Collection exceeds the IL2CPP generic row limit",
                ));
            }
            Ok(rows)
        }
    }
}

fn selected_alias_value<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let mut selected = None;
    for alias in aliases {
        let Some(candidate) = object.get(*alias) else {
            continue;
        };
        if let Some(existing) = selected {
            if existing != candidate {
                return Err(invalid(field, "Equivalent aliases disagree"));
            }
        } else {
            selected = Some(candidate);
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

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP generic constraints input is invalid.".into(),
        false,
        "Supply normalized IL2CPP generic constraint rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::conflicting_type_reference;
    use serde_json::json;

    #[test]
    fn rejects_type_spec_and_definition_aliases_across_nested_reference() {
        let reference = json!({
            "type_spec_index": 4,
            "type": { "typedef_index": 4 }
        });

        assert!(conflicting_type_reference(&reference));
    }

    #[test]
    fn accepts_repeated_aliases_within_one_type_index_domain() {
        let reference = json!({
            "type_spec_index": 4,
            "type": { "typeSpecIndex": 4 }
        });

        assert!(!conflicting_type_reference(&reference));
    }
}
