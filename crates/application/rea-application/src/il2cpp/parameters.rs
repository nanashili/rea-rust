//! Projection of IL2CPP method parameter ranges.
//!
//! The metadata reader owns decoding the binary parameter table.  This module
//! joins already decoded method and parameter rows, retaining every source
//! field and making incomplete or conflicting ranges explicit.

use crate::il2cpp::signature_renderer::{
    MethodFact, NamedTypeFact, ParameterFact, TypeFact, render_method_signature,
};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_parameters";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Join method `parameter_start`/`parameter_count` ranges with parameter rows.
///
/// `methods` and `parameters` may be supplied directly or below a `metadata`
/// object.  `parameter_start` and `parameter_count` are required method-row
/// fields; an explicit null or -1 start remains an unknown range. Optional
/// `type_facts` are indexed by `metadata_index` (or by the array position) and
/// are copied verbatim; this function never derives a type from a numeric
/// index.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let methods = rows(metadata, &["methods", "method_definitions"], "methods")?;
    let parameters = rows(
        metadata,
        &["parameters", "parameter_definitions"],
        "parameters",
    )?;
    let type_facts = root
        .get("type_facts")
        .or_else(|| metadata.get("type_facts"));
    let parameter_indices = ParameterIndexMap::build(&parameters);

    let mut used = BTreeSet::new();
    let mut overlap_rows = BTreeSet::new();
    let mut ranges = Vec::with_capacity(methods.len());
    let mut items = Vec::with_capacity(methods.len());
    let mut valid_ranges = 0usize;
    let mut missing_ranges = 0usize;
    let mut out_of_range = 0usize;

    for (method_row, method) in methods.iter().enumerate() {
        let object = method
            .as_object()
            .ok_or_else(|| invalid_row("methods", method_row, "Expected an object"))?;
        let start = signed_index(object, "parameter_start", "methods", method_row)?;
        let count = optional_count(object, "parameter_count", "methods", method_row)?;
        let method_index = object
            .get("metadata_index")
            .or_else(|| object.get("method_index"))
            .and_then(Value::as_u64);
        let mut item = Map::new();
        item.insert("method".into(), method.clone());
        item.insert(
            "method_index".into(),
            method_index.map_or(Value::Null, Value::from),
        );

        let (status, selected) = match (start, count) {
            (None, _) | (_, None) => {
                missing_ranges += 1;
                ("unknown", Vec::new())
            }
            (Some(start), Some(0)) => {
                if usize::try_from(start).map_or(true, |index| index > parameters.len()) {
                    out_of_range += 1;
                    ("out_of_range", Vec::new())
                } else {
                    valid_ranges += 1;
                    ("mapped", Vec::new())
                }
            }
            (Some(start), Some(count)) => {
                let end = start.checked_add(count).ok_or_else(|| {
                    invalid_row("methods", method_row, "parameter range overflows")
                })?;
                if parameter_indices.is_positional() && end > parameters.len() as u64 {
                    out_of_range += 1;
                    ("out_of_range", Vec::new())
                } else {
                    // A caller may provide a Number-safe range far larger than the
                    // retained table. Capacity must remain bounded by the rows we
                    // actually own; otherwise an explicit-index range could attempt
                    // an unbounded allocation before its first missing index is found.
                    let capacity = usize::try_from(count)
                        .unwrap_or(usize::MAX)
                        .min(parameters.len());
                    let mut selected = Vec::with_capacity(capacity);
                    let mut selected_indices = Vec::with_capacity(capacity);
                    let mut resolved = true;
                    for logical_index in start..end {
                        let Some(index) = parameter_indices.resolve(logical_index) else {
                            resolved = false;
                            break;
                        };
                        selected_indices.push(index);
                        selected.push(parameter_projection(&parameters[index], index, type_facts)?);
                    }
                    if !resolved {
                        missing_ranges += 1;
                        ("unknown", Vec::new())
                    } else {
                        for index in selected_indices {
                            if !used.insert(index) {
                                overlap_rows.insert(index);
                            }
                        }
                        valid_ranges += 1;
                        ranges.push((start, end, method_row));
                        ("mapped", selected)
                    }
                }
            }
        };

        let signature = assemble_signature(object, &selected, type_facts);
        item.insert("resolution".into(), Value::from(status));
        item.insert("signature".into(), signature);
        item.insert("parameters".into(), Value::Array(selected));
        items.push(Value::Object(item));
    }

    let unused: Vec<Value> = (0..parameters.len())
        .filter(|index| !used.contains(index))
        .map(Value::from)
        .collect();
    let overlapping: Vec<Value> = overlap_rows.iter().copied().map(Value::from).collect();
    let status = if out_of_range > 0 || missing_ranges > 0 || !overlapping.is_empty() {
        "partial"
    } else {
        "complete"
    };

    Ok(json!({
        "status": status,
        "items": items,
        "coverage": {
            "methods": methods.len(),
            "parameters": parameters.len(),
            "valid_ranges": valid_ranges,
            "missing_ranges": missing_ranges,
            "out_of_range_ranges": out_of_range,
            "overlapping_parameter_rows": overlapping,
            "unused_parameter_rows": unused,
            "range_count": ranges.len()
        }
    }))
}

/// Resolves method range values against explicit parameter indexes.
///
/// Decoder rows are normally ordered, but retained captures may preserve a
/// source index after reordering. When every row carries a unique explicit
/// parameter identity, range resolution follows that identity. Any partial or
/// conflicting explicit identity keeps ranges unresolved instead of guessing;
/// only rows with no explicit identity use physical order.
struct ParameterIndexMap {
    by_parameter_index: Option<BTreeMap<u64, usize>>,
    explicit_identity: bool,
}

impl ParameterIndexMap {
    fn build(parameters: &[Value]) -> Self {
        let mut by_parameter_index = BTreeMap::new();
        let mut has_explicit_index = false;

        for (row_index, row) in parameters.iter().enumerate() {
            let (parameter_index, has_identity) = parameter_identity(row);
            has_explicit_index |= has_identity;

            let Some(parameter_index) = parameter_index else {
                if has_identity {
                    return Self {
                        by_parameter_index: None,
                        explicit_identity: true,
                    };
                }
                continue;
            };

            if by_parameter_index
                .insert(parameter_index, row_index)
                .is_some()
            {
                return Self {
                    by_parameter_index: None,
                    explicit_identity: true,
                };
            }
        }

        if has_explicit_index && by_parameter_index.len() == parameters.len() {
            Self {
                by_parameter_index: Some(by_parameter_index),
                explicit_identity: true,
            }
        } else {
            Self {
                by_parameter_index: None,
                explicit_identity: has_explicit_index,
            }
        }
    }

    fn resolve(&self, logical_index: u64) -> Option<usize> {
        match &self.by_parameter_index {
            Some(indices) => indices.get(&logical_index).copied(),
            None if self.explicit_identity => None,
            None => usize::try_from(logical_index).ok(),
        }
    }

    fn is_positional(&self) -> bool {
        !self.explicit_identity
    }
}

/// Reads the aliases used by normalized parameter rows for one logical index.
///
/// Every present alias must agree. A malformed or conflicting alias is kept as
/// explicit-but-unresolved so callers do not fall back to physical row order.
fn parameter_identity(value: &Value) -> (Option<u64>, bool) {
    let Some(object) = value.as_object() else {
        return (None, false);
    };

    let mut identity = None;
    let mut has_identity = false;
    let mut conflict = false;
    for key in ["metadata_index", "parameter_index", "index"] {
        let Some(value) = object.get(key) else {
            continue;
        };
        has_identity = true;
        let Some(value) = index_value(value) else {
            conflict = true;
            continue;
        };
        if identity.is_some_and(|previous| previous != value) {
            conflict = true;
        } else {
            identity = Some(value);
        }
    }

    (identity.filter(|_| !conflict), has_identity)
}

fn parameter_projection(
    value: &Value,
    index: usize,
    type_facts: Option<&Value>,
) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_row("parameters", index, "Expected an object"))?;
    let (logical_index, _) = parameter_identity(value);
    let mut projected = object.clone();
    projected.insert("parameter_index".into(), Value::from(index));
    projected.insert(
        "parameter_identity".into(),
        json!({
            "metadata_index": object.get("metadata_index").and_then(index_value),
            "logical_index": logical_index,
            "source_offset": object.get("source_offset").and_then(index_value),
            "status": if logical_index.is_some() {
                "resolved"
            } else {
                "unknown"
            }
        }),
    );

    if !projected.contains_key("type_fact") {
        if let Some(type_index) = parameter_type_index(object) {
            let fact = lookup_type_fact(type_facts, type_index);
            projected.insert(
                "type_fact".into(),
                fact.unwrap_or_else(|| unknown_type_fact("type_fact_not_found")),
            );
        } else {
            projected.insert(
                "type_fact".into(),
                unknown_type_fact("parameter_type_index_missing"),
            );
        }
    } else if projected.get("type_fact").is_some_and(Value::is_null) {
        projected.insert(
            "type_fact".into(),
            unknown_type_fact("parameter_type_fact_unknown"),
        );
    }

    Ok(Value::Object(projected))
}

fn unknown_type_fact(reason: &str) -> Value {
    json!({"kind": "unknown", "reason": reason})
}

fn lookup_type_fact(type_facts: Option<&Value>, type_index: u64) -> Option<Value> {
    match type_facts? {
        Value::Array(rows) => rows
            .iter()
            .find_map(|row| {
                let object = row.as_object()?;
                let index = object
                    .get("metadata_index")
                    .or_else(|| object.get("type_index"))
                    .and_then(index_value)
                    .or_else(|| object.get("index").and_then(index_value));
                (index == Some(type_index)).then(|| {
                    object
                        .get("type_fact")
                        .cloned()
                        .unwrap_or_else(|| row.clone())
                })
            })
            .or_else(|| {
                let has_explicit_indices = rows.iter().any(|row| {
                    row.as_object().is_some_and(|object| {
                        ["metadata_index", "type_index", "index"]
                            .iter()
                            .any(|key| object.contains_key(*key))
                    })
                });
                (!has_explicit_indices)
                    .then(|| rows.get(usize::try_from(type_index).ok()?).cloned())
                    .flatten()
                    .map(extract_type_fact)
            }),
        Value::Object(object) => object
            .get(&type_index.to_string())
            .cloned()
            .map(extract_type_fact)
            .or_else(|| {
                object
                    .get("rows")
                    .and_then(|rows| lookup_type_fact(Some(rows), type_index))
            }),
        _ => None,
    }
}

fn extract_type_fact(row: Value) -> Value {
    row.as_object()
        .and_then(|object| object.get("type_fact"))
        .cloned()
        .unwrap_or(row)
}

fn parameter_type_index(object: &Map<String, Value>) -> Option<u64> {
    ["type_index", "type_definition_index", "type"]
        .iter()
        .find_map(|key| object.get(*key).and_then(index_value))
}

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

fn assemble_signature(
    method: &Map<String, Value>,
    parameters: &[Value],
    type_facts: Option<&Value>,
) -> Value {
    let unresolved =
        |reason: &str| json!({"status": "unresolved", "value": Value::Null, "reason": reason});
    let declaring_value = method_type_fact(
        method,
        &["declaring_type_fact", "declaring_type"],
        type_facts,
    );
    let Some(declaring_type) = declaring_value
        .as_ref()
        .and_then(type_fact_from_value)
        .and_then(named_type)
    else {
        return unresolved("declaring_type_fact_missing_or_unusable");
    };
    let Some(name) = method
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
    else {
        return unresolved("method_name_missing");
    };
    let Some(generic_arity) = method
        .get("generic_arity")
        .or_else(|| method.get("generic_parameter_count"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
    else {
        return unresolved("generic_arity_missing");
    };
    let Some(return_value) =
        method_type_fact(method, &["return_type_fact", "return_type"], type_facts)
    else {
        return unresolved("return_type_fact_missing");
    };
    let Some(return_type) = type_fact_from_value(&return_value) else {
        return unresolved("return_type_fact_unusable");
    };
    let mut parameter_facts = Vec::with_capacity(parameters.len());
    for parameter in parameters {
        let Some(object) = parameter.as_object() else {
            return unresolved("parameter_row_unusable");
        };
        let Some(type_value) = object.get("type_fact").filter(|value| !value.is_null()) else {
            return unresolved("parameter_type_fact_missing");
        };
        let Some(type_fact) = type_fact_from_value(type_value) else {
            return unresolved("parameter_type_fact_unusable");
        };
        parameter_facts.push(ParameterFact {
            name: object
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            type_fact: Some(type_fact),
        });
    }
    let method_fact = MethodFact {
        declaring_type: Some(declaring_type),
        name: Some(name.to_owned()),
        generic_arity: Some(generic_arity),
        parameter_arity: Some(parameter_facts.len()),
        return_type: Some(return_type),
        parameters: parameter_facts,
    };
    match render_method_signature(&method_fact) {
        Some(value) => json!({"status": "resolved", "value": value, "reason": Value::Null}),
        None => unresolved("signature_facts_incomplete"),
    }
}

fn method_type_fact(
    method: &Map<String, Value>,
    keys: &[&str],
    type_facts: Option<&Value>,
) -> Option<Value> {
    let value = keys.iter().find_map(|key| method.get(*key))?;
    resolve_type_fact_value(value, type_facts)
}

fn resolve_type_fact_value(value: &Value, type_facts: Option<&Value>) -> Option<Value> {
    if value.is_null() {
        return None;
    }
    if let Some(index) = index_value(value) {
        return lookup_type_fact(type_facts, index);
    }
    let object = value.as_object()?;
    if let Some(fact) = object.get("type_fact") {
        return Some(fact.clone());
    }
    Some(value.clone())
}

fn named_type(type_fact: TypeFact) -> Option<NamedTypeFact> {
    match type_fact {
        TypeFact::Named(value) => Some(value),
        _ => None,
    }
}

fn type_fact_from_value(value: &Value) -> Option<TypeFact> {
    if let Some(name) = value.as_str().filter(|name| !name.is_empty()) {
        return Some(TypeFact::Named(NamedTypeFact {
            namespace: None,
            name: Some(name.to_owned()),
            declaring_type: None,
            generic_arity: Some(0),
            generic_arguments: Vec::new(),
        }));
    }
    let object = value.as_object()?;
    match object.get("kind").and_then(Value::as_str) {
        Some("named") => {
            let arguments = object
                .get("generic_arguments")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(type_fact_from_value)
                        .collect::<Option<Vec<_>>>()
                })
                .flatten()
                .unwrap_or_default();
            let arity = object
                .get("generic_arity")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .or(Some(arguments.len()));
            let declaring = object
                .get("declaring_type")
                .and_then(type_fact_from_value)
                .and_then(named_type)
                .map(Box::new);
            Some(TypeFact::Named(NamedTypeFact {
                namespace: object
                    .get("namespace")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                name: object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                declaring_type: declaring,
                generic_arity: arity,
                generic_arguments: arguments,
            }))
        }
        Some("generic_parameter") => Some(TypeFact::GenericParameter {
            name: object
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            index: object
                .get("index")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok()),
            method: object
                .get("method")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        Some("array") => Some(TypeFact::Array {
            element: Box::new(type_fact_from_value(object.get("element")?)?),
            rank: object
                .get("rank")
                .and_then(Value::as_u64)
                .and_then(|value| usize::try_from(value).ok()),
        }),
        Some("byref") => Some(TypeFact::ByRef(Box::new(type_fact_from_value(
            object.get("element")?,
        )?))),
        Some("pointer") => Some(TypeFact::Pointer(Box::new(type_fact_from_value(
            object.get("element")?,
        )?))),
        Some("unknown") => Some(TypeFact::Unknown {
            reason: object
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_owned),
        }),
        _ => None,
    }
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    names: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let supplied = names
        .iter()
        .filter_map(|name| object.get(*name))
        .collect::<Vec<_>>();
    if supplied.windows(2).any(|values| values[0] != values[1]) {
        return Err(invalid(
            field,
            "Multiple row aliases disagree; the parameter table identity is ambiguous",
        ));
    }

    let value = supplied.first().copied();
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP parameter row limit",
        ));
    }
    Ok(rows)
}

fn signed_index(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let value = object.get(field).ok_or_else(|| {
        invalid_row(
            collection,
            row,
            "parameter_start is required and may be null or -1 when unknown",
        )
    })?;
    if value.as_i64() == Some(-1) || value.is_null() {
        return Ok(None);
    }
    let index = value.as_u64().ok_or_else(|| {
        invalid_row(
            collection,
            row,
            "parameter_start must be -1 or a non-negative integer",
        )
    })?;
    if index > MAX_SAFE_INTEGER {
        return Err(invalid_row(
            collection,
            row,
            "parameter_start must be at most Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(Some(index))
}

fn optional_count(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let value = object
        .get(field)
        .ok_or_else(|| invalid_row(collection, row, "parameter_count is required"))?;
    let count = value.as_u64().ok_or_else(|| {
        invalid_row(
            collection,
            row,
            "parameter_count must be an unsigned integer",
        )
    })?;
    if count > MAX_SAFE_INTEGER {
        return Err(invalid_row(
            collection,
            row,
            "parameter_count must be at most Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(Some(count))
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP parameter projection input is invalid.".into(),
        false,
        "Supply normalized IL2CPP method and parameter rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
