//! Projection of IL2CPP custom-attribute ranges and payload facts.
//!
//! The metadata decoder owns interpretation of the attribute tables.  This
//! module only joins rows that have already been decoded (and, optionally,
//! caller-supplied attribute-data bytes).  Attribute blobs are deliberately
//! kept opaque: executing constructors or deserializing arbitrary payloads
//! would cross the read-only analysis boundary.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_custom_attributes";
const MAX_ROWS: usize = 200_000;
const MAX_DATA_BYTES: usize = 64 * 1024 * 1024;
const MAX_BASE64_CHARS: usize = 89_478_488;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Project parsed attribute ranges and opaque attribute payloads.
///
/// `attribute_data_ranges` and `attribute_data` may be supplied directly or
/// below `metadata`.  A range identifies its owner with `owner_kind` and
/// `owner_index` (or an explicit member-index alias) and identifies its
/// payload by `data_start`/`data_size`.  Owner indices resolve only against
/// the matching retained metadata rows.  Missing or malformed links remain
/// visible in the result rather than selecting a nearby row.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    let inputs = projection_inputs(root)?;
    let projected = project_ranges(&inputs)?;

    Ok(finish_projection(
        projected,
        inputs.ranges.len(),
        inputs.data_rows,
    ))
}

struct ProjectionInputs<'a> {
    ranges: &'a [Value],
    metadata_indices: MetadataIndices,
    data_rows: Option<&'a [Value]>,
    data_bytes: Option<Vec<u8>>,
}

fn projection_inputs(root: &Map<String, Value>) -> Result<ProjectionInputs<'_>, Failure> {
    validate_input_shape(root)?;

    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);

    Ok(ProjectionInputs {
        ranges: rows(
            metadata,
            &["attribute_data_ranges", "attributeDataRanges", "ranges"],
            "attribute_data_ranges",
        )?,
        metadata_indices: metadata_indices(metadata)?,
        data_rows: optional_rows(metadata, &["attribute_data", "attributeData", "data"])?,
        data_bytes: decode_data_bytes(root, metadata)?,
    })
}

struct ProjectedRange {
    item: Value,
    span: (u64, u64, usize),
    unresolved: bool,
    unsupported: bool,
    used_data_row: Option<usize>,
}

#[derive(Default)]
struct ProjectedRanges {
    items: Vec<Value>,
    spans: Vec<(u64, u64, usize)>,
    unresolved: usize,
    unsupported: usize,
    used_data_rows: BTreeSet<usize>,
}

fn project_ranges(inputs: &ProjectionInputs<'_>) -> Result<ProjectedRanges, Failure> {
    let mut projected = ProjectedRanges {
        items: Vec::with_capacity(inputs.ranges.len()),
        spans: Vec::with_capacity(inputs.ranges.len()),
        ..ProjectedRanges::default()
    };

    for (row, range) in inputs.ranges.iter().enumerate() {
        let projection = project_range(
            range,
            row,
            &inputs.metadata_indices,
            inputs.data_rows,
            inputs.data_bytes.as_deref(),
        )?;

        projected.items.push(projection.item);
        projected.spans.push(projection.span);
        projected.unresolved += usize::from(projection.unresolved);
        projected.unsupported += usize::from(projection.unsupported);
        if let Some(index) = projection.used_data_row {
            projected.used_data_rows.insert(index);
        }
    }

    Ok(projected)
}

fn project_range(
    range: &Value,
    row: usize,
    metadata_indices: &MetadataIndices,
    data_rows: Option<&[Value]>,
    data_bytes: Option<&[u8]>,
) -> Result<ProjectedRange, Failure> {
    let object = range
        .as_object()
        .ok_or_else(|| invalid_row(row, "Expected an attribute range object"))?;
    if object.len() > 128 {
        return Err(invalid_row(
            row,
            "Attribute range exceeds the property limit",
        ));
    }

    validate_range_indices(object, row)?;

    let owner = owner_projection(object);
    let owner_status = owner_status(object, &owner, metadata_indices);
    let (start, size) = span_fields(object, row)?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| invalid_row(row, "Attribute-data span overflows"))?;
    ensure_safe_index(end, row, "Attribute-data span end")?;

    let span_status = span_status(data_bytes, end);
    let span = json!({
        "start": start,
        "size": size,
        "end": end,
        "status": span_status
    });
    let source_span = (start, end, row);

    let data_index = unsigned_alias_value(
        object,
        &["data_index", "attribute_data_index"],
        row,
        "Attribute-data index",
    )?;
    let linked_data_row = resolve_data_row(data_index, data_rows);
    let linked_data = linked_data_row.map(|(_, row)| row);
    let payload = payload_projection(object, linked_data, data_bytes, start, end, row)?;
    let unresolved = owner_status != "resolved"
        || payload.get("status").and_then(Value::as_str) == Some("unresolved");
    let unsupported = payload.get("status").and_then(Value::as_str) == Some("unsupported");
    let used_data_row = linked_data_row.map(|(index, _)| index);

    Ok(ProjectedRange {
        item: json!({
            "row": row,
            "source": range,
            "owner": owner,
            "owner_status": owner_status,
            "constructor": constructor_links(object),
            "span": span,
            "payload": payload
        }),
        span: source_span,
        unresolved,
        unsupported,
        used_data_row,
    })
}

fn span_status(data_bytes: Option<&[u8]>, end: u64) -> &'static str {
    match data_bytes {
        Some(bytes) if end <= bytes.len() as u64 => "mapped",
        Some(_) => "out_of_bounds",
        None => "unresolved",
    }
}

fn resolve_data_row<'a>(
    data_index: Option<u64>,
    data_rows: Option<&'a [Value]>,
) -> Option<(usize, &'a Value)> {
    let data_rows = data_rows?;
    let index = usize::try_from(data_index?).ok()?;
    data_rows.get(index).map(|row| (index, row))
}

fn finish_projection(
    mut projected: ProjectedRanges,
    range_count: usize,
    data_rows: Option<&[Value]>,
) -> Value {
    let overlapping = overlapping_range_rows(&mut projected.spans);
    let unused_data_rows = unused_data_rows(data_rows, &projected.used_data_rows);
    let status = if projected.unresolved > 0 || !overlapping.is_empty() || projected.unsupported > 0
    {
        "partial"
    } else {
        "complete"
    };

    json!({
        "operation": OPERATION,
        "status": status,
        "items": projected.items,
        "coverage": {
            "ranges": range_count,
            "unresolved": projected.unresolved,
            "unsupported_payloads": projected.unsupported,
            "overlapping_ranges": overlapping.len(),
            "unused_data_rows": unused_data_rows.len()
        },
        "diagnostics": {
            "overlapping_range_rows": overlapping.into_iter().map(Value::from).collect::<Vec<_>>(),
            "unused_data_rows": unused_data_rows
        },
        "limitations": [
            "Attribute payloads remain opaque; constructors are never executed and arbitrary blobs are never deserialized.",
            "A range is resolved only when its owner and byte span are explicit and unambiguous."
        ]
    })
}

fn unused_data_rows(data_rows: Option<&[Value]>, used_data_rows: &BTreeSet<usize>) -> Vec<Value> {
    data_rows
        .map(|rows| {
            (0..rows.len())
                .filter(|index| !used_data_rows.contains(index))
                .map(Value::from)
                .collect()
        })
        .unwrap_or_default()
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
        return Err(invalid(field, "Collection exceeds the row limit"));
    }
    Ok(rows)
}

fn optional_rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
) -> Result<Option<&'a [Value]>, Failure> {
    let Some(value) = selected_alias_value(object, aliases, "attribute_data")? else {
        return Ok(None);
    };
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("attribute_data", "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "attribute_data",
            "Collection exceeds the row limit",
        ));
    }
    Ok(Some(rows))
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

fn metadata_indices(metadata: &Map<String, Value>) -> Result<MetadataIndices, Failure> {
    let mut indices = MetadataIndices::default();
    for (kind, aliases) in [
        ("type", ["types", "type_definitions", "typeDefinitions"]),
        (
            "method",
            ["methods", "method_definitions", "methodDefinitions"],
        ),
        ("field", ["fields", "field_definitions", "fieldDefinitions"]),
        ("event", ["events", "event_definitions", "eventDefinitions"]),
        (
            "property",
            ["properties", "property_definitions", "propertyDefinitions"],
        ),
        (
            "parameter",
            [
                "parameters",
                "parameter_definitions",
                "parameterDefinitions",
            ],
        ),
    ] {
        let Some(value) = selected_alias_value(metadata, &aliases, kind)? else {
            continue;
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(kind, "Expected a metadata row array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid(kind, "Collection exceeds the row limit"));
        }
        let entry = indices.by_kind.entry(kind).or_default();
        for (row, value) in rows.iter().enumerate() {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row_for(kind, row, "Expected a metadata row object"))?;
            let Some(index) = metadata_row_index(object, kind, row)? else {
                continue;
            };
            *entry.entry(index).or_default() += 1;
        }
    }
    Ok(indices)
}

fn metadata_row_index(
    object: &Map<String, Value>,
    kind: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let aliases = match kind {
        "type" => [
            "type_index",
            "typeIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        "method" => [
            "method_index",
            "methodIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        "field" => [
            "field_index",
            "fieldIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        "event" => [
            "event_index",
            "eventIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        "property" => [
            "property_index",
            "propertyIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        "parameter" => [
            "parameter_index",
            "parameterIndex",
            "metadata_index",
            "metadataIndex",
            "index",
        ],
        _ => [
            "index",
            "metadata_index",
            "metadataIndex",
            "source_index",
            "sourceIndex",
        ],
    };
    let mut selected = None;
    for alias in aliases {
        let Some(value) = object.get(alias).filter(|value| !value.is_null()) else {
            continue;
        };
        let index = value
            .as_u64()
            .filter(|index| *index <= MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                invalid_row_for(
                    kind,
                    row,
                    "Metadata row index aliases must be safe non-negative integers",
                )
            })?;
        if selected.is_some_and(|existing| existing != index) {
            return Err(invalid_row_for(
                kind,
                row,
                "Metadata row index aliases disagree",
            ));
        }
        selected = Some(index);
    }
    Ok(selected)
}

fn overlapping_range_rows(spans: &mut [(u64, u64, usize)]) -> BTreeSet<usize> {
    spans.sort_unstable_by_key(|(start, end, row)| (*start, *end, *row));

    let mut active_ends = BTreeMap::<u64, Vec<usize>>::new();
    let mut unmarked_active_ends = BTreeMap::<u64, Vec<usize>>::new();
    let mut overlapping_rows = vec![false; spans.len()];

    for &(start, end, row) in spans.iter() {
        if start >= end {
            continue;
        }

        remove_expired_ranges(&mut active_ends, start);
        remove_expired_ranges(&mut unmarked_active_ends, start);

        if active_ends.is_empty() {
            unmarked_active_ends.entry(end).or_default().push(row);
        } else {
            overlapping_rows[row] = true;
            for earlier_row in unmarked_active_ends.values().flatten() {
                overlapping_rows[*earlier_row] = true;
            }
            unmarked_active_ends.clear();
        }

        active_ends.entry(end).or_default().push(row);
    }

    overlapping_rows
        .into_iter()
        .enumerate()
        .filter_map(|(row, overlaps)| overlaps.then_some(row))
        .collect()
}

fn remove_expired_ranges(active: &mut BTreeMap<u64, Vec<usize>>, start: u64) {
    while let Some((&end, _)) = active.first_key_value() {
        if end > start {
            return;
        }
        active.remove(&end);
    }
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    const INPUT_FIELDS: &[&str] = &[
        "attribute_data_ranges",
        "attributeDataRanges",
        "ranges",
        "attribute_data",
        "attributeData",
        "data",
        "attribute_data_base64",
        "data_base64",
        "types",
        "type_definitions",
        "typeDefinitions",
        "methods",
        "method_definitions",
        "methodDefinitions",
        "fields",
        "field_definitions",
        "fieldDefinitions",
        "events",
        "event_definitions",
        "eventDefinitions",
        "properties",
        "property_definitions",
        "propertyDefinitions",
        "parameters",
        "parameter_definitions",
        "parameterDefinitions",
    ];
    const WRAPPED_FIELDS: &[&str] = &["metadata", "attribute_data_base64", "data_base64"];

    if root.contains_key("metadata") {
        reject_unknown_fields(root, WRAPPED_FIELDS, "input")?;
        let metadata = root
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        reject_unknown_fields(metadata, INPUT_FIELDS, "metadata")?;
        if !INPUT_FIELDS[..3]
            .iter()
            .any(|field| metadata.contains_key(*field))
        {
            return Err(invalid("metadata", "Expected attribute-data ranges"));
        }
        return Ok(());
    }

    reject_unknown_fields(root, INPUT_FIELDS, "input")?;
    if !INPUT_FIELDS[..3]
        .iter()
        .any(|field| root.contains_key(*field))
    {
        return Err(invalid("input", "Expected attribute-data ranges"));
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
        return Err(invalid(
            &format!("{field}.{name}"),
            "Unknown field is not allowed",
        ));
    }
    Ok(())
}

#[derive(Default)]
struct MetadataIndices {
    by_kind: BTreeMap<&'static str, BTreeMap<u64, usize>>,
}

fn invalid_row_for(kind: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{kind}[{row}]"), reason)
}

fn decode_data_bytes<'a>(
    root: &'a Map<String, Value>,
    metadata: &'a Map<String, Value>,
) -> Result<Option<Vec<u8>>, Failure> {
    let mut value = None;
    for candidate in [
        root.get("attribute_data_base64"),
        root.get("data_base64"),
        metadata.get("attribute_data_base64"),
        metadata.get("data_base64"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(existing) = value {
            if existing != candidate {
                return Err(invalid(
                    "attribute_data_base64",
                    "Equivalent data aliases disagree",
                ));
            }
        } else {
            value = Some(candidate);
        }
    }
    let Some(value) = value else {
        return Ok(None);
    };
    let encoded = value
        .as_str()
        .ok_or_else(|| invalid("attribute_data_base64", "Expected a base64 string"))?;
    if encoded.len() > MAX_BASE64_CHARS {
        return Err(invalid(
            "attribute_data_base64",
            "Base64 data exceeds the 64 MiB encoded limit",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid("attribute_data_base64", "Malformed base64 data"))?;
    if bytes.len() > MAX_DATA_BYTES {
        return Err(invalid(
            "attribute_data_base64",
            "Data exceeds the 64 MiB limit",
        ));
    }
    Ok(Some(bytes))
}

fn span_fields(object: &Map<String, Value>, row: usize) -> Result<(u64, u64), Failure> {
    let start = unsigned_alias_value(
        object,
        &["data_start", "attribute_data_start", "start"],
        row,
        "Attribute-data start",
    )?
    .ok_or_else(|| invalid_row(row, "Missing non-negative data start"))?;
    let size = unsigned_alias_value(
        object,
        &["data_size", "attribute_data_size", "size", "count"],
        row,
        "Attribute-data size",
    )?
    .ok_or_else(|| invalid_row(row, "Missing non-negative data size"))?;
    Ok((start, size))
}

fn unsigned_alias_value(
    object: &Map<String, Value>,
    aliases: &[&str],
    row: usize,
    field: &str,
) -> Result<Option<u64>, Failure> {
    let mut selected = None;

    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let index = value
            .as_u64()
            .ok_or_else(|| invalid_row(row, &format!("{alias} must be a non-negative integer")))?;
        ensure_safe_index(index, row, field)?;

        if selected.is_some_and(|existing| existing != index) {
            return Err(invalid_row(
                row,
                &format!("Equivalent {field} aliases disagree"),
            ));
        }
        selected = Some(index);
    }

    Ok(selected)
}

fn ensure_safe_index(value: u64, row: usize, field: &str) -> Result<(), Failure> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid_row(
            row,
            &format!("{field} exceeds Number.MAX_SAFE_INTEGER"),
        ));
    }
    Ok(())
}

fn validate_range_indices(object: &Map<String, Value>, row: usize) -> Result<(), Failure> {
    if let Some(value) = object.get("owner_kind") {
        if !value.is_string() {
            return Err(invalid_row(row, "owner_kind must be a string"));
        }
    }

    for field in [
        "owner_index",
        "type_index",
        "typeIndex",
        "method_index",
        "methodIndex",
        "field_index",
        "fieldIndex",
        "event_index",
        "eventIndex",
        "property_index",
        "propertyIndex",
        "parameter_index",
        "parameterIndex",
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(value) = value.as_i64() else {
            return Err(invalid_row(row, &format!("{field} must be an integer")));
        };
        if value < -(MAX_SAFE_INTEGER as i64) || value > MAX_SAFE_INTEGER as i64 {
            return Err(invalid_row(
                row,
                &format!("{field} exceeds the safe integer range"),
            ));
        }
    }
    Ok(())
}

fn owner_projection(object: &Map<String, Value>) -> Value {
    let explicit_kind = object.get("owner_kind").and_then(Value::as_str);
    let Ok(explicit_indices) = consistent_index_aliases(object, &["owner_index"]) else {
        return Value::Null;
    };
    let Some(typed_candidates) = typed_owner_candidates(object) else {
        return Value::Null;
    };

    if let Some(kind) = explicit_kind {
        if typed_candidates
            .iter()
            .any(|candidate| candidate.kind != kind)
        {
            return Value::Null;
        }
        let typed_index = typed_candidates.first().map(|candidate| candidate.index);
        let Some(index) = explicit_indices.or(typed_index) else {
            return Value::Null;
        };
        if typed_index.is_some() && explicit_indices != typed_index {
            return Value::Null;
        }
        return json!({ "kind": kind, "index": index });
    }

    if explicit_indices.is_some() || typed_candidates.len() != 1 {
        return Value::Null;
    }
    let candidate = &typed_candidates[0];
    json!({ "kind": candidate.kind, "index": candidate.index })
}

struct TypedOwnerCandidate {
    kind: &'static str,
    index: i64,
}

fn consistent_index_aliases(
    object: &Map<String, Value>,
    aliases: &[&str],
) -> Result<Option<i64>, ()> {
    let claims = aliases
        .iter()
        .filter_map(|alias| object.get(*alias))
        .collect::<Vec<_>>();
    if claims.iter().any(|value| value.as_i64().is_none()) {
        return Err(());
    }
    let values = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).and_then(Value::as_i64))
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return Err(());
    }
    Ok(values.into_iter().next())
}

fn typed_owner_candidates(object: &Map<String, Value>) -> Option<Vec<TypedOwnerCandidate>> {
    let mut candidates = Vec::new();
    let typed_aliases = [
        ("type", ["type_index", "typeIndex"]),
        ("method", ["method_index", "methodIndex"]),
        ("field", ["field_index", "fieldIndex"]),
        ("event", ["event_index", "eventIndex"]),
        ("property", ["property_index", "propertyIndex"]),
        ("parameter", ["parameter_index", "parameterIndex"]),
    ];

    for (kind, aliases) in typed_aliases {
        let Ok(index) = consistent_index_aliases(object, &aliases) else {
            return None;
        };
        if let Some(index) = index {
            candidates.push(TypedOwnerCandidate { kind, index });
        }
    }

    Some(candidates)
}

fn owner_status(
    source: &Map<String, Value>,
    owner: &Value,
    metadata: &MetadataIndices,
) -> &'static str {
    if owner_claim_conflicted(source) {
        return "invalid";
    }

    let Some(object) = owner.as_object() else {
        return "unknown";
    };

    let Some(kind) = object.get("kind").and_then(Value::as_str) else {
        return "invalid";
    };
    let Some(index) = object.get("index").and_then(Value::as_i64) else {
        return "invalid";
    };
    if index < 0 {
        return "invalid";
    }
    if !matches!(
        kind,
        "type" | "method" | "field" | "event" | "property" | "parameter"
    ) {
        return "invalid";
    }

    let Some(indices) = metadata.by_kind.get(kind) else {
        return "unknown";
    };
    match indices.get(&(index as u64)).copied().unwrap_or(0) {
        0 => "unknown",
        1 => "resolved",
        // Multiple metadata rows claim the same identity. Preserve the raw
        // range and report the ownership conflict as invalid rather than
        // selecting an arbitrary row.
        _ => "invalid",
    }
}

fn owner_claim_conflicted(object: &Map<String, Value>) -> bool {
    let Some(typed_candidates) = typed_owner_candidates(object) else {
        return true;
    };
    if typed_candidates.len() > 1 {
        return true;
    }

    let explicit_kind = object.get("owner_kind").and_then(Value::as_str);
    if explicit_kind.is_some_and(|kind| {
        typed_candidates
            .first()
            .is_some_and(|candidate| candidate.kind != kind)
    }) {
        return true;
    }

    let Ok(explicit_index) = consistent_index_aliases(object, &["owner_index"]) else {
        return true;
    };
    explicit_index.is_some_and(|index| {
        typed_candidates
            .first()
            .is_some_and(|candidate| candidate.index != index)
    })
}

fn constructor_links(object: &Map<String, Value>) -> Value {
    let mut links = Map::new();
    for (output, aliases) in [
        (
            "type_index",
            &[
                "attribute_type_index",
                "constructor_type_index",
                "attributeTypeIndex",
            ][..],
        ),
        (
            "method_index",
            &["constructor_method_index", "constructorMethodIndex"][..],
        ),
    ] {
        let value = constructor_value(object, &aliases);
        links.insert(output.into(), value);
    }
    Value::Object(links)
}

fn constructor_value(object: &Map<String, Value>, aliases: &[&str]) -> Value {
    let nested = object.get("constructor").and_then(Value::as_object);
    let mut selected = None;

    for source in [Some(object), nested].into_iter().flatten() {
        for alias in aliases {
            let Some(candidate) = source.get(*alias) else {
                continue;
            };
            if selected.is_some_and(|existing| existing != candidate) {
                return Value::Null;
            }
            selected = Some(candidate);
        }
    }

    selected.cloned().unwrap_or(Value::Null)
}

fn payload_projection(
    object: &Map<String, Value>,
    data: Option<&Value>,
    bytes: Option<&[u8]>,
    start: u64,
    end: u64,
    row: usize,
) -> Result<Value, Failure> {
    match (object.get("payload"), object.get("blob")) {
        (Some(payload), Some(blob)) if payload != blob => {
            return Ok(json!({
                "status": "unresolved",
                "sources": {
                    "payload": payload,
                    "blob": blob
                },
                "reason": "Payload aliases disagree"
            }));
        }
        (Some(value), _) | (_, Some(value)) => {
            return Ok(json!({
                "status": "unsupported",
                "source": value,
                "reason": "Opaque attribute payload"
            }));
        }
        (None, None) => {}
    }
    if let Some(value) = data {
        return Ok(json!({
            "status": "unsupported",
            "source": value,
            "reason": "Opaque attribute-data row"
        }));
    }
    let Some(bytes) = bytes else {
        return Ok(json!({
            "status": "unresolved",
            "reason": "No attribute-data bytes supplied"
        }));
    };
    if end > bytes.len() as u64 {
        return Ok(json!({
            "status": "unresolved",
            "reason": "Span exceeds supplied attribute-data bytes"
        }));
    }
    let slice = &bytes[start as usize..end as usize];
    Ok(json!({
        "status": "opaque",
        "data_base64": base64::engine::general_purpose::STANDARD.encode(slice),
        "bytes": slice.len(),
        "row": row
    }))
}

fn invalid_row(row: usize, reason: &str) -> Failure {
    invalid(&format!("attribute_data_ranges[{row}]"), reason)
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP custom-attribute input is invalid.".into(),
        false,
        "Supply parsed attribute ranges and opaque data facts and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
