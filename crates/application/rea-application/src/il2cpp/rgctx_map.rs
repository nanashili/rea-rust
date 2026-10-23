//! Read-only projection of caller-supplied IL2CPP RGCTX facts.
//!
//! This module intentionally stops at the metadata boundary.  It does not
//! locate a `CodeGenModule`, read a binary, resolve a pointer, or infer what a
//! generic method does.  A provider may supply either a normalized report or a
//! retained Evidence record; the source token, range and index of every fact
//! are carried through unchanged.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_il2cpp_rgctx_map";
pub const DEFAULT_MAX_RECORDS: usize = 50_000;
pub const MAX_RECORDS: usize = 200_000;

/// Project a report supplied by an adapter.  The report may contain one
/// `CodeGenModule` object or an array under `modules`.
pub fn project_records(input: &Value, max_records: usize) -> Result<Value, Failure> {
    let limit = bounded_limit(max_records)?;
    let modules = module_values(input)?;
    let mut projected = Vec::new();
    let mut examined_ranges = 0usize;
    let mut examined_values = 0usize;
    let mut unresolved_values = 0usize;
    let mut truncated = false;

    for (module_position, module) in modules.iter().enumerate() {
        let object = module
            .as_object()
            .ok_or_else(|| invalid("CodeGenModule records must be objects"))?;
        let module_name = optional_text(object, &["module", "module_name", "name"]);
        let ranges = array_field(object, &["rgctx_ranges", "rgctxRanges", "ranges"])?;
        let values = array_field(object, &["rgctx_values", "rgctxValues", "data", "values"])?;

        let remaining = limit.saturating_sub(examined_ranges + examined_values);
        if remaining == 0 {
            truncated = true;
            break;
        }
        let range_budget = remaining.min(ranges.len());
        let value_budget = remaining.saturating_sub(range_budget).min(values.len());
        if range_budget < ranges.len() || value_budget < values.len() {
            truncated = true;
        }

        let projected_ranges = ranges
            .iter()
            .take(range_budget)
            .enumerate()
            .map(|(position, value)| parse_range(value, position))
            .collect::<Result<Vec<_>, _>>()?;
        let mut projected_values = values
            .iter()
            .take(value_budget)
            .enumerate()
            .map(|(position, value)| parse_value(value, position))
            .collect::<Result<Vec<_>, _>>()?;
        mark_duplicate_value_indices(&mut projected_values);
        let projected_ranges = correlate_ranges(projected_ranges, &projected_values);

        examined_ranges += projected_ranges.len();
        examined_values += projected_values.len();
        unresolved_values += projected_values
            .iter()
            .filter(|value| value.get("resolution").and_then(Value::as_str) == Some("unresolved"))
            .count();
        projected.push(json!({
            "module": module_name,
            "module_index": module_position,
            "rgctx_ranges": projected_ranges,
            "rgctx_values": projected_values,
        }));
    }

    Ok(json!({
        "modules": projected,
        "coverage": coverage(examined_ranges, examined_values, unresolved_values, truncated),
        "limitations": limitations(),
    }))
}

/// Project a retained Evidence value without reopening the recorded source.
/// The Evidence envelope is authenticated by the caller's retention layer;
/// this function only extracts and validates its normalized result.
pub fn project_captured_evidence(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("captured input must be an object"))?;
    let evidence = object
        .get("evidence")
        .ok_or_else(|| invalid("captured input requires evidence"))?;
    let normalized = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("Evidence must contain normalized_result"))?;
    project_records(normalized, DEFAULT_MAX_RECORDS)
}

fn module_values(input: &Value) -> Result<Vec<Value>, Failure> {
    if let Some(array) = input.as_array() {
        return Ok(array.to_vec());
    }
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be a CodeGenModule object or array"))?;
    if let Some(modules) = object.get("modules") {
        return modules
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("modules must be an array"));
    }
    Ok(vec![input.clone()])
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    names: &[&str],
) -> Result<&'a Vec<Value>, Failure> {
    let value = names.iter().find_map(|name| object.get(*name));
    value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("CodeGenModule must contain RGCTX ranges and values arrays"))
}

fn parse_range(value: &Value, position: usize) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("rgctx range must be an object"))?;
    let start = required_u64(object, &["start", "rgctx_start", "first"])?;
    let count = required_u64(object, &["count", "rgctx_count", "length"])?;
    let end = start
        .checked_add(count)
        .ok_or_else(|| invalid("rgctx range overflows its index space"))?;
    let metadata_start = optional_u64(
        object,
        &[
            "metadata_start",
            "metadata_index_start",
            "rgctx_metadata_start",
        ],
    )?;
    let metadata_count = optional_u64(
        object,
        &[
            "metadata_count",
            "metadata_index_count",
            "rgctx_metadata_count",
        ],
    )?;
    if metadata_start.is_some() != metadata_count.is_some() {
        return Err(invalid(
            "rgctx range metadata bounds require both start and count",
        ));
    }
    let metadata_end = metadata_start
        .zip(metadata_count)
        .map(|(start, count)| {
            start
                .checked_add(count)
                .ok_or_else(|| invalid("rgctx range metadata bounds overflow their index space"))
        })
        .transpose()?;
    Ok(json!({
        "source": source_fields(object),
        "position": position,
        "start": start,
        "count": count,
        "end_exclusive": end,
        "metadata_start": metadata_start,
        "metadata_count": metadata_count,
        "metadata_end_exclusive": metadata_end,
        "owner": owner_fields(object),
    }))
}

fn parse_value(value: &Value, position: usize) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("rgctx value must be an object"))?;
    let index = required_u64(object, &["index", "rgctx_index"])?;
    let metadata_index = optional_u64(
        object,
        &["metadata_index", "metadataIndex", "rgctx_metadata_index"],
    )?;
    let kind = object
        .get("kind")
        .or_else(|| object.get("data_kind"))
        .cloned()
        .unwrap_or(Value::Null);
    let category = match kind.as_str() {
        Some("type") | Some("Type") | Some("rgctx_type") => "type",
        Some("method") | Some("Method") | Some("rgctx_method") => "method",
        _ => match kind.as_u64() {
            // Il2CppRGCTXDataType values: type/class are type facts, while
            // method/constrained are method facts.  Array and invalid entries
            // remain unknown until a provider supplies a stronger identity.
            Some(1 | 2) => "type",
            Some(3 | 5) => "method",
            _ => "unknown",
        },
    };
    let explicit_reference = object
        .get("reference")
        .or_else(|| object.get("resolved"))
        .cloned();
    let has_explicit_reference = explicit_reference.is_some();
    let type_index = optional_u64(object, &["type_index", "typeIndex", "rgctx_type_index"])?;
    let method_index = optional_u64(
        object,
        &["method_index", "methodIndex", "rgctx_method_index"],
    )?;
    let has_conflicting_index_kinds = type_index.is_some() && method_index.is_some();
    let reference = explicit_reference.clone().unwrap_or_else(|| {
        if has_conflicting_index_kinds {
            return Value::Null;
        }
        type_index
            .map(|index| json!({"kind": "type", "index": index}))
            .or_else(|| method_index.map(|index| json!({"kind": "method", "index": index})))
            .unwrap_or(Value::Null)
    });
    let resolution = if has_conflicting_index_kinds {
        "ambiguous"
    } else if reference.is_null() {
        "unresolved"
    } else if has_explicit_reference || type_index.is_some() || method_index.is_some() {
        "resolved"
    } else {
        "unknown"
    };
    Ok(json!({
        "source": source_fields(object),
        "position": position,
        "index": index,
        "metadata_index": metadata_index,
        "kind": category,
        "kind_source": kind,
        "reference": reference,
        "resolution": resolution,
        "resolution_reason": if has_conflicting_index_kinds {
            Value::from("Both type and method RGCTX identities were supplied.")
        } else {
            Value::Null
        },
        "type_index": type_index,
        "method_index": method_index,
        "owner": owner_fields(object),
    }))
}

fn correlate_ranges(mut ranges: Vec<Value>, values: &[Value]) -> Vec<Value> {
    for range in &mut ranges {
        let Some(object) = range.as_object_mut() else {
            continue;
        };
        let Some(start) = object.get("start").and_then(Value::as_u64) else {
            continue;
        };
        let Some(end) = object.get("end_exclusive").and_then(Value::as_u64) else {
            continue;
        };
        let matching_values = values
            .iter()
            .filter(|value| {
                let in_range = range_contains_value(object, value, start, end);
                in_range && owners_match(object.get("owner"), value.get("owner"))
            })
            .cloned()
            .collect::<Vec<_>>();
        let owner_unknown_values = values
            .iter()
            .filter(|value| {
                let in_range = range_contains_value(object, value, start, end);
                in_range
                    && owners_match(object.get("owner"), value.get("owner"))
                    && owner_correlation_is_uncertain(object.get("owner"), value.get("owner"))
            })
            .count();
        let matches_metadata_range = object
            .get("metadata_start")
            .and_then(Value::as_u64)
            .is_some()
            && object
                .get("metadata_end_exclusive")
                .and_then(Value::as_u64)
                .is_some();
        let duplicate_value_indices =
            duplicate_value_identity_count(&matching_values, matches_metadata_range);
        let owner_status = if owner_unknown_values > 0 || duplicate_value_indices > 0 {
            "ambiguous"
        } else if matching_values.is_empty() {
            "unresolved"
        } else {
            "exact"
        };
        object.insert("values".into(), Value::Array(matching_values));
        object.insert(
            "owner_correlation".into(),
            json!({
                "status": owner_status,
                "uncertain_values": owner_unknown_values,
                "duplicate_value_indices": duplicate_value_indices,
            }),
        );
    }
    ranges
}

fn range_contains_value(range: &Map<String, Value>, value: &Value, start: u64, end: u64) -> bool {
    if let (Some(metadata_start), Some(metadata_end)) = (
        range.get("metadata_start").and_then(Value::as_u64),
        range.get("metadata_end_exclusive").and_then(Value::as_u64),
    ) {
        return value
            .get("metadata_index")
            .and_then(Value::as_u64)
            .is_some_and(|index| index >= metadata_start && index < metadata_end);
    }

    value
        .get("index")
        .and_then(Value::as_u64)
        .is_some_and(|index| index >= start && index < end)
}

fn owner_correlation_is_uncertain(
    range_owner: Option<&Value>,
    value_owner: Option<&Value>,
) -> bool {
    let range = range_owner.and_then(Value::as_object);
    let value = value_owner.and_then(Value::as_object);
    let kind_unknown = |owner: Option<&Map<String, Value>>| {
        owner
            .and_then(|owner| owner.get("kind"))
            .and_then(Value::as_str)
            .map_or(true, |kind| kind == "unknown")
    };
    let reference_unknown = |owner: Option<&Map<String, Value>>| {
        owner
            .and_then(|owner| owner.get("reference"))
            .map_or(true, Value::is_null)
    };
    kind_unknown(range)
        || kind_unknown(value)
        || reference_unknown(range)
        || reference_unknown(value)
}

fn owners_match(range_owner: Option<&Value>, value_owner: Option<&Value>) -> bool {
    let Some(range_owner) = range_owner.and_then(Value::as_object) else {
        return true;
    };
    let Some(value_owner) = value_owner.and_then(Value::as_object) else {
        return true;
    };
    let range_kind = range_owner.get("kind").and_then(Value::as_str);
    let value_kind = value_owner.get("kind").and_then(Value::as_str);
    if matches!(range_kind, Some("type" | "method")) && range_kind != value_kind {
        return false;
    }
    let range_reference = range_owner.get("reference");
    let value_reference = value_owner.get("reference");
    match (range_reference, value_reference) {
        (Some(range), Some(value)) if !range.is_null() && !value.is_null() => range == value,
        _ => true,
    }
}

fn owner_fields(object: &Map<String, Value>) -> Value {
    let owner_kind = object
        .get("owner_kind")
        .or_else(|| object.get("context_kind"))
        .or_else(|| object.get("generic_kind"))
        .and_then(Value::as_str)
        .map(|kind| match kind {
            "type" | "Type" | "rgctx_type" => "type",
            "method" | "Method" | "rgctx_method" => "method",
            _ => "unknown",
        })
        .unwrap_or("unknown");
    let owner = object
        .get("owner")
        .or_else(|| object.get("owner_reference"))
        .or_else(|| object.get("owner_token"))
        .or_else(|| object.get("type_token"))
        .or_else(|| object.get("method_token"))
        .cloned()
        .unwrap_or(Value::Null);
    let resolution = if owner.is_null() {
        "unresolved"
    } else if owner_kind == "unknown" {
        "ambiguous"
    } else {
        "resolved"
    };
    json!({
        "kind": owner_kind,
        "reference": owner,
        "resolution": resolution,
    })
}

fn mark_duplicate_value_indices(values: &mut [Value]) {
    let mut counts = BTreeMap::new();
    for value in values.iter() {
        if let Some(index) = value.get("index").and_then(Value::as_u64) {
            *counts.entry(index).or_insert(0usize) += 1;
        }
    }

    let mut metadata_counts = BTreeMap::new();
    for value in values.iter() {
        if let Some(index) = value.get("metadata_index").and_then(Value::as_u64) {
            *metadata_counts.entry(index).or_insert(0usize) += 1;
        }
    }

    for value in values {
        let Some(index) = value.get("index").and_then(Value::as_u64) else {
            continue;
        };
        if counts.get(&index).copied().unwrap_or(0) < 2 {
            if value
                .get("metadata_index")
                .and_then(Value::as_u64)
                .and_then(|metadata_index| metadata_counts.get(&metadata_index))
                .copied()
                .unwrap_or(0)
                < 2
            {
                continue;
            }
        }
        let Some(object) = value.as_object_mut() else {
            continue;
        };
        object.insert("resolution".into(), Value::from("ambiguous"));
        object.insert(
            "resolution_reason".into(),
            Value::from("Multiple RGCTX value rows share an identity index."),
        );
    }
}

fn duplicate_value_identity_count(values: &[Value], use_metadata_index: bool) -> usize {
    let mut counts = BTreeMap::new();
    let identity_field = if use_metadata_index {
        "metadata_index"
    } else {
        "index"
    };
    for value in values {
        if let Some(index) = value.get(identity_field).and_then(Value::as_u64) {
            *counts.entry(index).or_insert(0usize) += 1;
        }
    }
    counts
        .values()
        .filter_map(|count| count.checked_sub(1))
        .sum()
}

fn source_fields(object: &Map<String, Value>) -> Value {
    let mut source = Map::new();
    for name in [
        "token",
        "source_token",
        "range",
        "source_range",
        "start",
        "rgctx_start",
        "first",
        "count",
        "rgctx_count",
        "length",
        "metadata_start",
        "metadata_index_start",
        "rgctx_metadata_start",
        "metadata_count",
        "metadata_index_count",
        "rgctx_metadata_count",
        "index",
        "rgctx_index",
        "type_index",
        "typeIndex",
        "rgctx_type_index",
        "method_index",
        "methodIndex",
        "rgctx_method_index",
        "source_index",
        "metadata_index",
        "metadataIndex",
        "rgctx_metadata_index",
    ] {
        if let Some(value) = object.get(name) {
            source.insert(name.to_owned(), value.clone());
        }
    }
    Value::Object(source)
}

fn required_u64(object: &Map<String, Value>, names: &[&str]) -> Result<u64, Failure> {
    let mut parsed = Vec::new();
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let number = value
            .as_u64()
            .ok_or_else(|| invalid("rgctx range/value index fields must be unsigned integers"))?;
        parsed.push((*name, number));
    }

    let Some((_, first)) = parsed.first().copied() else {
        return Err(invalid(
            "rgctx range/value index fields must be unsigned integers",
        ));
    };
    if parsed.iter().any(|(_, value)| *value != first) {
        return Err(invalid(
            "rgctx range/value index aliases contain conflicting values",
        ));
    }
    Ok(first)
}

fn optional_u64(object: &Map<String, Value>, names: &[&str]) -> Result<Option<u64>, Failure> {
    let mut parsed = Vec::new();
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let number = value
            .as_u64()
            .ok_or_else(|| invalid("rgctx metadata identity fields must be unsigned integers"))?;
        parsed.push((*name, number));
    }

    let Some((_, first)) = parsed.first().copied() else {
        return Ok(None);
    };
    if parsed.iter().any(|(_, value)| *value != first) {
        return Err(invalid(
            "rgctx metadata identity aliases contain conflicting values",
        ));
    }
    Ok(Some(first))
}

fn optional_text(object: &Map<String, Value>, names: &[&str]) -> Value {
    names
        .iter()
        .find_map(|name| object.get(*name).filter(|value| value.is_string()))
        .cloned()
        .unwrap_or(Value::Null)
}

fn coverage(ranges: usize, values: usize, unresolved: usize, truncated: bool) -> Value {
    json!({
        "status": if truncated { "partial" } else { "complete" },
        "ranges_examined": ranges,
        "values_examined": values,
        "unresolved_values": unresolved,
        "reason": if truncated { "record_limit_reached" } else { "caller_supplied_records_examined" },
    })
}

fn limitations() -> Vec<&'static str> {
    vec![
        "Only caller-supplied CodeGenModule records or retained Evidence are examined.",
        "Missing or unrecognized generic kinds remain unknown; no call behavior is inferred.",
        "References are derived from explicit type or method indices only when the caller supplies no reference; conflicting identity kinds remain ambiguous.",
    ]
}

fn bounded_limit(value: usize) -> Result<usize, Failure> {
    if value == 0 || value > MAX_RECORDS {
        return Err(invalid("max_records must be between 1 and 200,000"));
    }
    Ok(value)
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide caller-supplied IL2CPP RGCTX records or retained Evidence.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
