//! Pure correlation of IL2CPP `MethodSpec` metadata facts.
//!
//! A MethodSpec identifies a generic managed method and its declaring type
//! instantiation.  It is metadata identity only: this module deliberately
//! never turns a MethodSpec into a native address or assumes that a generic
//! method has been emitted by the binary.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "map_il2cpp_method_specs";
const MAX_ROWS: usize = 200_000;

/// Join MethodSpec rows with the metadata facts that describe their generic
/// method and instantiations.  Direct arrays and `metadata` wrappers are both
/// accepted.  Missing facts remain unresolved and duplicate identities remain
/// ambiguous instead of being selected by row order.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    validate_input_shape(root)?;

    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let specs = required_rows(metadata, &["method_specs"], "method_specs")?;
    let generic_methods = optional_rows(metadata, &["generic_methods"], "generic_methods")?;
    let method_definitions = optional_rows(metadata, &["methods"], "methods")?;
    let type_definitions = optional_rows(metadata, &["types"], "types")?;
    let instances = optional_rows(metadata, &["generic_instances"], "generic_instances")?;
    let argument_rows = optional_rows(
        metadata,
        &[
            "generic_arguments",
            "type_arguments",
            "genericArguments",
            "type_specs",
            "typeSpecifications",
            "typespecs",
        ],
        "generic_arguments",
    )?;
    let type_descriptors = optional_rows(
        metadata,
        &[
            "type_descriptors",
            "typeDescriptors",
            "type_specs",
            "typeSpecifications",
            "typespecs",
        ],
        "type_descriptors",
    )?;

    let generic_by_index = index_rows(
        &generic_methods,
        "generic_methods",
        generic_key,
        &[
            "generic_method_index",
            "genericMethodIndex",
            "generic_index",
            "genericIndex",
            "metadata_index",
            "index",
        ],
    )?;
    let generic_by_method = index_rows(
        &generic_methods,
        "generic_methods",
        method_definition_key,
        &[
            "method_definition_index",
            "methodDefinitionIndex",
            "method_index",
            "methodIndex",
            "metadata_index",
            "index",
        ],
    )?;
    let methods_by_index = index_rows(
        &method_definitions,
        "methods",
        method_definition_key,
        &[
            "method_definition_index",
            "methodDefinitionIndex",
            "method_index",
            "methodIndex",
            "metadata_index",
            "index",
        ],
    )?;
    let types_by_index = index_rows(
        &type_definitions,
        "types",
        metadata_index_key,
        &[
            "metadata_index",
            "type_index",
            "index",
            "method_spec_index",
            "methodSpecIndex",
        ],
    )?;
    let descriptors_by_index = index_rows(
        &type_descriptors,
        "type_descriptors",
        metadata_index_key,
        &[
            "metadata_index",
            "type_index",
            "index",
            "method_spec_index",
            "methodSpecIndex",
        ],
    )?;
    let instances_by_index = index_rows(
        &instances,
        "generic_instances",
        instance_key,
        &[
            "generic_instance_index",
            "genericInstanceIndex",
            "instance_index",
            "instanceIndex",
            "metadata_index",
            "index",
        ],
    )?;
    let arguments_by_index = index_rows(
        &argument_rows,
        "generic_arguments",
        argument_key,
        &[
            "argument_index",
            "generic_argument_index",
            "type_argument_index",
            "index",
        ],
    )?;

    let mut items = Vec::with_capacity(specs.len());
    let mut resolved = 0usize;
    let mut unknown = 0usize;
    let mut ambiguous = 0usize;

    for (row, spec) in specs.iter().enumerate() {
        let object = spec
            .as_object()
            .ok_or_else(|| invalid_row("method_specs", row, "Expected an object"))?;
        let spec_index = required_key(object, "method_specs", row)?;
        let method_index = optional_key(
            object,
            method_definition_key,
            &["method_definition_index", "methodDefinitionIndex"],
            "method_specs",
            row,
        )?;
        let class_index = optional_key(
            object,
            class_definition_key,
            &["type_definition_index", "typeDefinitionIndex"],
            "method_specs",
            row,
        )?;
        let generic_index = optional_key(
            object,
            generic_key,
            &[
                "generic_method_index",
                "genericMethodIndex",
                "generic_index",
                "genericIndex",
            ],
            "method_specs",
            row,
        )?;
        let explicit_instance_index = optional_key(
            object,
            instance_key,
            &[
                "generic_instance_index",
                "genericInstanceIndex",
                "instance_index",
                "instanceIndex",
            ],
            "method_specs",
            row,
        )?;
        let method_instance_index = optional_key(
            object,
            instance_key,
            &[
                "method_instantiation_index",
                "methodInstantiationIndex",
                "method_instance_index",
                "methodInstanceIndex",
                "method_index",
                "methodIndex",
            ],
            "method_specs",
            row,
        )?;
        let class_instance_index = optional_key(
            object,
            instance_key,
            &[
                "class_instantiation_index",
                "classInstantiationIndex",
                "class_instance_index",
                "classInstanceIndex",
                "class_index",
                "classIndex",
            ],
            "method_specs",
            row,
        )?;
        let method_match =
            method_index.map_or(Match::Missing, |index| lookup(&methods_by_index, index));
        let type_match = class_index.map_or(Match::Missing, |index| lookup(&types_by_index, index));
        let class_instance_match =
            class_instance_index.map_or(Match::Missing, |index| lookup(&instances_by_index, index));
        let method_instance_match = combine_matches(
            explicit_instance_index
                .map_or(Match::Missing, |index| lookup(&instances_by_index, index)),
            method_instance_index
                .map_or(Match::Missing, |index| lookup(&instances_by_index, index)),
        );
        let generic_match = generic_method_match(
            generic_index,
            method_index,
            method_instance_match,
            &generic_by_index,
            &generic_by_method,
        );
        let class_arguments = project_generic_arguments(
            object,
            class_instance_match,
            &arguments_by_index,
            &types_by_index,
            &descriptors_by_index,
            argument_rows.len(),
            "class",
        )?;
        let method_arguments = project_generic_arguments(
            object,
            method_instance_match,
            &arguments_by_index,
            &types_by_index,
            &descriptors_by_index,
            argument_rows.len(),
            "method",
        )?;

        let state = resolution(
            generic_match,
            method_match,
            type_match,
            class_instance_match,
            method_instance_match,
            class_arguments.status,
            method_arguments.status,
        );
        match state {
            "resolved" => resolved += 1,
            "ambiguous" => ambiguous += 1,
            _ => unknown += 1,
        }

        let mut item = Map::new();
        item.insert("method_spec_index".into(), Value::from(spec_index));
        item.insert("method_spec".into(), spec.clone());
        item.insert("generic_method".into(), match_value(generic_match));
        item.insert("method_definition".into(), match_value(method_match));
        item.insert("declaring_type".into(), match_value(type_match));
        item.insert(
            "generic_instance".into(),
            match_value(method_instance_match),
        );
        item.insert("class_instance".into(), match_value(class_instance_match));
        item.insert("class_arguments".into(), class_arguments.value);
        item.insert("method_arguments".into(), method_arguments.value);
        item.insert("resolution".into(), Value::from(state));
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if unknown > 0 || ambiguous > 0 { "partial" } else { "complete" },
        "items": items,
        "coverage": {
            "method_specs": specs.len(),
            "resolved": resolved,
            "unknown": unknown,
            "ambiguous": ambiguous,
            "generic_methods": generic_methods.len(),
            "method_definitions": method_definitions.len(),
            "type_definitions": type_definitions.len(),
            "generic_instances": instances.len(),
        },
        "limitations": [
            "MethodSpec identity does not prove a native generic body or pointer exists.",
            "Generic arguments are retained from supplied rows and are not inferred from names."
        ]
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(metadata) = root.get("metadata") {
        let metadata = metadata
            .as_object()
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        reject_unknown_fields(root, &["metadata"], "input")?;
        reject_unknown_fields(
            metadata,
            &[
                "method_specs",
                "generic_methods",
                "methods",
                "types",
                "generic_instances",
                "generic_arguments",
                "type_arguments",
                "genericArguments",
                "type_specs",
                "typeSpecifications",
                "typespecs",
                "type_descriptors",
                "typeDescriptors",
            ],
            "metadata",
        )?;
        return Ok(());
    }

    reject_unknown_fields(
        root,
        &[
            "method_specs",
            "generic_methods",
            "methods",
            "types",
            "generic_instances",
            "generic_arguments",
            "type_arguments",
            "genericArguments",
            "type_specs",
            "typeSpecifications",
            "typespecs",
            "type_descriptors",
            "typeDescriptors",
        ],
        "input",
    )
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

#[derive(Clone, Copy)]
enum Match<'a> {
    Missing,
    One(&'a Value),
    Ambiguous,
}

fn resolution(
    generic: Match<'_>,
    method: Match<'_>,
    type_definition: Match<'_>,
    class_instance: Match<'_>,
    method_instance: Match<'_>,
    class_arguments: ArgumentStatus,
    method_arguments: ArgumentStatus,
) -> &'static str {
    if [
        generic,
        method,
        type_definition,
        class_instance,
        method_instance,
    ]
    .into_iter()
    .any(|item| matches!(item, Match::Ambiguous))
    {
        return "ambiguous";
    }
    if [class_arguments, method_arguments]
        .into_iter()
        .any(|status| matches!(status, ArgumentStatus::Ambiguous))
    {
        return "ambiguous";
    }
    if matches!(generic, Match::Missing)
        || matches!(method, Match::Missing)
        || matches!(type_definition, Match::Missing)
        || matches!(class_instance, Match::Missing)
        || matches!(method_instance, Match::Missing)
        || matches!(class_arguments, ArgumentStatus::Unknown)
        || matches!(method_arguments, ArgumentStatus::Unknown)
        || matches!(class_arguments, ArgumentStatus::Unresolved)
        || matches!(method_arguments, ArgumentStatus::Unresolved)
    {
        "unknown"
    } else {
        "resolved"
    }
}

#[derive(Clone, Copy)]
enum ArgumentStatus {
    NotProvided,
    Unknown,
    Unresolved,
    Ambiguous,
    Resolved,
}

struct ArgumentProjection {
    status: ArgumentStatus,
    value: Value,
}

fn project_generic_arguments(
    spec: &Map<String, Value>,
    instance: Match<'_>,
    argument_index: &BTreeMap<u64, Vec<&Value>>,
    type_index: &BTreeMap<u64, Vec<&Value>>,
    descriptor_index: &BTreeMap<u64, Vec<&Value>>,
    argument_count: usize,
    kind: &str,
) -> Result<ArgumentProjection, Failure> {
    let instance_object = match instance {
        Match::One(row) => row.as_object(),
        _ => None,
    };
    let references = if kind == "class" {
        spec.get("class_argument_indices")
            .or_else(|| spec.get("classArgumentIndices"))
            .or_else(|| spec.get("class_type_indices"))
            .or_else(|| instance_object.and_then(|row| row.get("type_indices")))
            .or_else(|| instance_object.and_then(|row| row.get("typeIndices")))
            .or_else(|| instance_object.and_then(|row| row.get("generic_argument_indices")))
            .or_else(|| instance_object.and_then(|row| row.get("argument_indices")))
    } else {
        spec.get("method_argument_indices")
            .or_else(|| spec.get("methodArgumentIndices"))
            .or_else(|| spec.get("method_type_indices"))
            .or_else(|| instance_object.and_then(|row| row.get("type_indices")))
            .or_else(|| instance_object.and_then(|row| row.get("typeIndices")))
            .or_else(|| instance_object.and_then(|row| row.get("generic_argument_indices")))
            .or_else(|| instance_object.and_then(|row| row.get("argument_indices")))
    };

    let Some(references) = references else {
        return Ok(ArgumentProjection {
            status: if argument_count == 0 {
                ArgumentStatus::NotProvided
            } else {
                ArgumentStatus::Unknown
            },
            value: serde_json::json!({ "status": if argument_count == 0 { "not_provided" } else { "unknown" }, "arguments": [] }),
        });
    };
    let references = references
        .as_array()
        .ok_or_else(|| invalid("generic_argument_indices", "Expected an array"))?;

    let mut arguments = Vec::with_capacity(references.len());
    let mut missing = Vec::new();
    let mut ambiguous = false;
    let mut unresolved_types = false;
    for (position, reference) in references.iter().enumerate() {
        let Some(index) = parse_index_value(reference) else {
            let source = reference.as_object().ok_or_else(|| {
                invalid(
                    &format!("generic_argument_indices[{position}]"),
                    "Expected a non-negative integer or argument object",
                )
            })?;
            unresolved_types = true;
            arguments.push(serde_json::json!({
                "position": position,
                "status": "unresolved",
                "source": source,
            }));
            continue;
        };
        match argument_index.get(&index) {
            Some(rows) if rows.len() == 1 => {
                let projected =
                    project_argument(index, position, rows[0], type_index, descriptor_index);
                unresolved_types |=
                    projected.get("resolution_status").and_then(Value::as_str) != Some("resolved");
                arguments.push(projected);
            }
            Some(rows) => {
                ambiguous = true;
                arguments.push(serde_json::json!({
                    "position": position,
                    "argument_index": index,
                    "status": "ambiguous",
                    "rows": rows,
                }));
            }
            None => {
                missing.push(index);
                arguments.push(serde_json::json!({
                    "position": position,
                    "argument_index": index,
                    "status": "unresolved",
                }));
            }
        }
    }
    let status = if ambiguous {
        ArgumentStatus::Ambiguous
    } else if !missing.is_empty() || unresolved_types {
        ArgumentStatus::Unresolved
    } else {
        ArgumentStatus::Resolved
    };
    let status_name = match status {
        ArgumentStatus::Resolved => "resolved",
        ArgumentStatus::Ambiguous => "ambiguous",
        ArgumentStatus::Unresolved => "unresolved",
        _ => "unknown",
    };
    Ok(ArgumentProjection {
        status,
        value: serde_json::json!({
            "status": status_name,
            "arguments": arguments,
            "missing_indices": missing,
        }),
    })
}

fn project_argument(
    index: u64,
    position: usize,
    source: &Value,
    type_index: &BTreeMap<u64, Vec<&Value>>,
    descriptor_index: &BTreeMap<u64, Vec<&Value>>,
) -> Value {
    let type_reference = source
        .as_object()
        .and_then(|row| {
            row.get("type_index")
                .or_else(|| row.get("type_definition_index"))
                .or_else(|| row.get("type"))
        })
        .cloned()
        .unwrap_or(Value::Null);
    let type_match = type_reference
        .as_u64()
        .or_else(|| parse_index_value(&type_reference))
        .map_or(Match::Missing, |key| lookup(type_index, key));
    let descriptor_match = type_reference
        .as_u64()
        .or_else(|| parse_index_value(&type_reference))
        .map_or(Match::Missing, |key| lookup(descriptor_index, key));
    let resolution_match = combine_matches(type_match, descriptor_match);
    let resolution_status = match resolution_match {
        Match::One(_) => "resolved",
        Match::Ambiguous => "ambiguous",
        Match::Missing => "unresolved",
    };
    serde_json::json!({
        "position": position,
        "argument_index": index,
        "source": source,
        "type_reference": type_reference,
        "type": match_value(type_match),
        "type_descriptor": match_value(descriptor_match),
        "resolution_status": resolution_status,
    })
}

fn match_value(value: Match<'_>) -> Value {
    match value {
        Match::One(row) => row.clone(),
        Match::Missing => Value::Null,
        Match::Ambiguous => serde_json::json!({ "status": "ambiguous" }),
    }
}

fn generic_method_match<'a>(
    generic_index: Option<u64>,
    method_index: Option<u64>,
    method_instance: Match<'_>,
    generic_by_index: &BTreeMap<u64, Vec<&'a Value>>,
    generic_by_method: &BTreeMap<u64, Vec<&'a Value>>,
) -> Match<'a> {
    let direct_match = combine_matches(
        generic_index.map_or(Match::Missing, |index| lookup(generic_by_index, index)),
        method_index.map_or(Match::Missing, |index| lookup(generic_by_method, index)),
    );
    if !matches!(direct_match, Match::Missing) {
        return direct_match;
    }

    match method_instance {
        Match::Missing => Match::Missing,
        Match::Ambiguous => Match::Ambiguous,
        Match::One(instance) => {
            generic_method_from_instance(instance, generic_by_index, generic_by_method)
        }
    }
}

fn generic_method_from_instance<'a>(
    instance: &Value,
    generic_by_index: &BTreeMap<u64, Vec<&'a Value>>,
    generic_by_method: &BTreeMap<u64, Vec<&'a Value>>,
) -> Match<'a> {
    let Some(object) = instance.as_object() else {
        return Match::Missing;
    };

    let generic_match = match first_index(
        object,
        &[
            "generic_method_index",
            "genericMethodIndex",
            "generic_index",
            "genericIndex",
        ],
    ) {
        IndexSelection::Missing => Match::Missing,
        IndexSelection::Ambiguous => Match::Ambiguous,
        IndexSelection::One(index) => lookup(generic_by_index, index),
    };
    let method_match = match first_index(
        object,
        &[
            "method_definition_index",
            "methodDefinitionIndex",
            "method_index",
            "methodIndex",
        ],
    ) {
        IndexSelection::Missing => Match::Missing,
        IndexSelection::Ambiguous => Match::Ambiguous,
        IndexSelection::One(index) => lookup(generic_by_method, index),
    };

    combine_matches(generic_match, method_match)
}

fn combine_matches<'a>(left: Match<'a>, right: Match<'a>) -> Match<'a> {
    match (left, right) {
        (Match::Ambiguous, _) | (_, Match::Ambiguous) => Match::Ambiguous,
        (Match::Missing, other) | (other, Match::Missing) => other,
        (Match::One(left), Match::One(right)) if std::ptr::eq(left, right) => Match::One(left),
        (Match::One(_), Match::One(_)) => Match::Ambiguous,
    }
}

enum IndexSelection {
    Missing,
    One(u64),
    Ambiguous,
}

fn first_index(object: &Map<String, Value>, names: &[&str]) -> IndexSelection {
    let mut selected = None;
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(index) = parse_index_value(value) else {
            return IndexSelection::Ambiguous;
        };
        match selected {
            None => selected = Some(index),
            Some(previous) if previous == index => {}
            Some(_) => return IndexSelection::Ambiguous,
        }
    }
    selected.map_or(IndexSelection::Missing, IndexSelection::One)
}

fn lookup<'a>(index: &BTreeMap<u64, Vec<&'a Value>>, key: u64) -> Match<'a> {
    match index.get(&key).map(Vec::as_slice) {
        None => Match::Missing,
        Some([row]) => Match::One(row),
        Some(_) => Match::Ambiguous,
    }
}

type RowKey = fn(&Map<String, Value>) -> Option<u64>;

fn index_rows<'a>(
    rows: &'a [Value],
    field: &str,
    key: RowKey,
    aliases: &[&str],
) -> Result<BTreeMap<u64, Vec<&'a Value>>, Failure> {
    let mut index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row(field, row, "Expected an object"))?;
        if let Some(key) = key(object) {
            index.entry(key).or_insert_with(Vec::new).push(value);
        } else if aliases
            .iter()
            .any(|alias| object.get(*alias).is_some_and(|value| !value.is_null()))
        {
            return Err(invalid_row(
                field,
                row,
                "Identity aliases are malformed or conflicting",
            ));
        }
    }
    Ok(index)
}

fn required_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = aliases.iter().find_map(|alias| object.get(*alias));
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    bounded_rows(rows, field)
}

fn optional_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Vec<Value>, Failure> {
    let Some(value) = aliases.iter().find_map(|alias| object.get(*alias)) else {
        return Ok(Vec::new());
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    bounded_rows(rows, field).map(|rows| rows.to_vec())
}

fn bounded_rows<'a>(rows: &'a [Value], field: &str) -> Result<&'a [Value], Failure> {
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the MethodSpec row limit",
        ));
    }
    Ok(rows)
}

fn required_key(object: &Map<String, Value>, field: &str, row: usize) -> Result<u64, Failure> {
    method_spec_key(object).ok_or_else(|| {
        invalid_row(
            field,
            row,
            "method_spec_index or index must be a non-negative integer",
        )
    })
}

fn method_spec_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "metadata_index",
            "index",
            "method_spec_index",
            "methodSpecIndex",
        ],
    )
}

fn optional_key(
    object: &Map<String, Value>,
    key: RowKey,
    names: &[&str],
    field: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    if let Some(value) = key(object) {
        return Ok(Some(value));
    }
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        if !value.is_null() {
            return Err(invalid_row(
                field,
                row,
                "Index fields must be non-negative integers",
            ));
        }
    }
    Ok(None)
}

fn metadata_index_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "metadata_index",
            "type_index",
            "index",
            "method_spec_index",
            "methodSpecIndex",
        ],
    )
}

fn generic_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "generic_method_index",
            "genericMethodIndex",
            "generic_index",
            "genericIndex",
            "metadata_index",
            "index",
        ],
    )
}

fn method_definition_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "method_definition_index",
            "methodDefinitionIndex",
            "method_index",
            "methodIndex",
            "metadata_index",
            "index",
        ],
    )
}

fn class_definition_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "class_index",
            "classIndex",
            "type_definition_index",
            "typeDefinitionIndex",
            "metadata_index",
            "index",
        ],
    )
}

fn instance_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "generic_instance_index",
            "genericInstanceIndex",
            "instance_index",
            "instanceIndex",
            "metadata_index",
            "index",
        ],
    )
}

fn argument_key(object: &Map<String, Value>) -> Option<u64> {
    consistent_index(
        object,
        &[
            "argument_index",
            "generic_argument_index",
            "type_argument_index",
            "index",
        ],
    )
}

fn consistent_index(object: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    match first_index(object, names) {
        IndexSelection::One(index) => Some(index),
        IndexSelection::Missing | IndexSelection::Ambiguous => None,
    }
}

/// Parse the caller's preserved metadata index representation without
/// converting malformed values into an absent row. Unity captures commonly
/// encode indices as decimal or hexadecimal text, while the JSON projection
/// also accepts native non-negative integers.
fn parse_index_value(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse::<u64>().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP MethodSpec mapping input is invalid.".into(),
        false,
        "Supply normalized MethodSpec and generic metadata rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
